class SignalingClient {
  constructor() {
    this.ws = null;
    this.peerId = null;
    this.peers = new Map();
    this.remoteStreams = new Map();
    this.pendingRemoteCandidates = new Map();
    this.peerNames = new Map();
    this.localStream = null;
    this.iceServers = [
      { urls: "stun:stun.cloudflare.com:3478" },
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" },
    ];
    this._signalQueue = Promise.resolve();
    this.onRemoteStream = null;
    this.onConnectionStateChange = null;
    this.onPeerLeft = null;
    this.onChatMessage = null;
  }

  async _loadIceServers() {
    try {
      const res = await fetch("/turn/credentials");
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.iceServers) && data.iceServers.length > 0) {
          this.iceServers = data.iceServers;
          const hasTurn = this.iceServers.some((s) => {
            const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
            return urls.some((u) => typeof u === "string" && u.startsWith("turn"));
          });
          console.log(`[signaling] Loaded ICE servers (TURN relay active: ${hasTurn})`);
        }
      }
    } catch (err) {
      console.warn("[signaling] Using default STUN servers:", err);
    }
  }

  async connect(roomId, localStream, userName = "Participant") {
    this.localStream = localStream;
    await this._loadIceServers();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws?room=${encodeURIComponent(roomId)}&name=${encodeURIComponent(userName)}`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }
      this._signalQueue = this._signalQueue
        .then(() => this._handleMessage(data))
        .catch((err) => console.error("[signaling] Queue error:", err));
    };

    this.ws.onclose = () => {
      console.log("[signaling] WebSocket closed");
      this.peers.forEach((_, peerId) => this._removePeer(peerId));
    };

    this.ws.onerror = (err) => {
      console.error("[signaling] WebSocket error:", err);
    };

    return new Promise((resolve, reject) => {
      this.ws.onopen = () => resolve();
      this.ws.onerror = () => reject(new Error("WebSocket connection failed"));
    });
  }

  async _handleMessage(data) {
    switch (data.type) {
      case "connected":
        this.peerId = data.peerId;
        if (Array.isArray(data.peers)) {
          data.peers.forEach((p) => {
            if (p.peerId && p.name) this.peerNames.set(p.peerId, p.name);
          });
        }
        console.log(`[signaling] Connected as ${this.peerId}, ${data.peerCount} peer(s) in room`);
        break;

      case "peer-joined":
        if (data.name) this.peerNames.set(data.peerId, data.name);
        await this._createOffer(data.peerId);
        break;

      case "peer-left":
        this._removePeer(data.peerId);
        if (this.onPeerLeft) this.onPeerLeft(data.peerId);
        break;

      case "offer": {
        const remotePeerId = data.fromPeerId || data.peerId;
        if (data.fromName) this.peerNames.set(remotePeerId, data.fromName);
        await this._handleOffer(remotePeerId, data.sdp);
        break;
      }

      case "answer": {
        const remotePeerId = data.fromPeerId || data.peerId;
        if (data.fromName) this.peerNames.set(remotePeerId, data.fromName);
        await this._handleAnswer(remotePeerId, data.sdp);
        break;
      }

      case "ice-candidate": {
        const remotePeerId = data.fromPeerId || data.peerId;
        await this._handleIceCandidate(remotePeerId, data.candidate);
        break;
      }

      case "chat":
        if (this.onChatMessage) this.onChatMessage(data.sender, data.text);
        break;
    }
  }

  _send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  _createPeerConnection(peerId) {
    if (this.peers.has(peerId)) {
      this._removePeer(peerId);
    }

    const pc = new RTCPeerConnection({
      iceServers: this.iceServers,
      iceCandidatePoolSize: 4,
    });

    pc._canSendLocalCandidates = false;
    pc._localCandidateBuffer = [];

    this.peers.set(peerId, pc);

    if (this.localStream) {
      this.localStream.getTracks().forEach((track) => {
        pc.addTrack(track, this.localStream);
      });
    }

    pc.onicecandidate = (event) => {
      if (event.candidate && event.candidate.candidate) {
        const payload = {
          type: "ice-candidate",
          targetPeerId: peerId,
          candidate: event.candidate.toJSON ? event.candidate.toJSON() : event.candidate,
        };
        if (pc._canSendLocalCandidates) {
          this._send(payload);
        } else {
          pc._localCandidateBuffer.push(payload);
        }
      }
    };

    pc.ontrack = (event) => {
      let stream = this.remoteStreams.get(peerId);
      if (!stream) {
        stream = new MediaStream();
        this.remoteStreams.set(peerId, stream);
      }

      if (event.streams && event.streams[0]) {
        event.streams[0].getTracks().forEach((t) => {
          if (!stream.getTracks().includes(t)) {
            stream.addTrack(t);
          }
        });
      } else if (event.track) {
        if (!stream.getTracks().includes(event.track)) {
          stream.addTrack(event.track);
        }
      }

      const peerName = this.peerNames.get(peerId) || "Connected Participant";
      if (this.onRemoteStream) {
        this.onRemoteStream(peerId, stream, peerName);
      }
    };

    pc.onconnectionstatechange = () => {
      console.log(`[signaling] Peer ${peerId} connectionState: ${pc.connectionState}`);
      if (this.onConnectionStateChange) {
        const peerName = this.peerNames.get(peerId) || "Connected Participant";
        this.onConnectionStateChange(peerId, pc.connectionState, peerName);
      }
    };

    pc.oniceconnectionstatechange = () => {
      console.log(`[signaling] Peer ${peerId} iceConnectionState: ${pc.iceConnectionState}`);
    };

    return pc;
  }

  _flushLocalCandidates(pc) {
    pc._canSendLocalCandidates = true;
    while (pc._localCandidateBuffer.length > 0) {
      const payload = pc._localCandidateBuffer.shift();
      this._send(payload);
    }
  }

  async _flushRemoteCandidates(peerId, pc) {
    const queue = this.pendingRemoteCandidates.get(peerId);
    if (!queue || queue.length === 0) return;

    this.pendingRemoteCandidates.delete(peerId);
    for (const candidate of queue) {
      try {
        await pc.addIceCandidate(candidate);
      } catch (err) {
        console.warn("[signaling] Failed to add queued ICE candidate:", err);
      }
    }
  }

  async _createOffer(peerId) {
    try {
      const pc = this._createPeerConnection(peerId);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      this._send({
        type: "offer",
        targetPeerId: peerId,
        sdp: { type: offer.type, sdp: offer.sdp },
      });

      this._flushLocalCandidates(pc);
    } catch (err) {
      console.error("[signaling] Error creating offer:", err);
    }
  }

  async _handleOffer(peerId, sdp) {
    try {
      const pc = this._createPeerConnection(peerId);
      await pc.setRemoteDescription(sdp);
      await this._flushRemoteCandidates(peerId, pc);

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      this._send({
        type: "answer",
        targetPeerId: peerId,
        sdp: { type: answer.type, sdp: answer.sdp },
      });

      this._flushLocalCandidates(pc);
    } catch (err) {
      console.error("[signaling] Error handling offer:", err);
    }
  }

  async _handleAnswer(peerId, sdp) {
    try {
      const pc = this.peers.get(peerId);
      if (!pc) return;
      await pc.setRemoteDescription(sdp);
      await this._flushRemoteCandidates(peerId, pc);
    } catch (err) {
      console.error("[signaling] Error handling answer:", err);
    }
  }

  async _handleIceCandidate(peerId, candidate) {
    if (!candidate || !candidate.candidate) return;
    const pc = this.peers.get(peerId);

    if (!pc || !pc.remoteDescription || !pc.remoteDescription.type) {
      if (!this.pendingRemoteCandidates.has(peerId)) {
        this.pendingRemoteCandidates.set(peerId, []);
      }
      this.pendingRemoteCandidates.get(peerId).push(candidate);
      return;
    }

    try {
      await pc.addIceCandidate(candidate);
    } catch (err) {
      console.warn("[signaling] Error adding ICE candidate:", err);
    }
  }

  _removePeer(peerId) {
    const pc = this.peers.get(peerId);
    if (pc) {
      pc.close();
      this.peers.delete(peerId);
    }
    this.remoteStreams.delete(peerId);
    this.pendingRemoteCandidates.delete(peerId);
    this.peerNames.delete(peerId);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.peers.forEach((_, peerId) => this._removePeer(peerId));
  }

  sendChatMessage(sender, text) {
    this._send({ type: "chat", sender, text });
  }

  replaceVideoTrack(newTrack) {
    for (const pc of this.peers.values()) {
      const sender = pc.getSenders().find((s) => s.track && s.track.kind === "video");
      if (sender) sender.replaceTrack(newTrack);
    }
  }
}

if (typeof window !== "undefined") {
  window.SignalingClient = SignalingClient;
}