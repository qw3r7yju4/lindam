class SignalingClient {
  constructor() {
    this.ws = null;
    this.peerId = null;
    this.peers = new Map();
    this.remoteStreams = new Map();
    this.pendingCandidates = new Map();
    this.peerNames = new Map();
    this.localStream = null;
    this.onRemoteStream = null;
    this.onConnectionStateChange = null;
    this.onPeerLeft = null;
    this.onChatMessage = null;
  }

  async connect(roomId, localStream, userName = "Participant") {
    this.localStream = localStream;
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
      this._handleMessage(data);
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

  _handleMessage(data) {
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
        this._createOffer(data.peerId);
        break;

      case "peer-left":
        this._removePeer(data.peerId);
        if (this.onPeerLeft) this.onPeerLeft(data.peerId);
        break;

      case "offer": {
        const remotePeerId = data.fromPeerId || data.peerId;
        if (data.fromName) this.peerNames.set(remotePeerId, data.fromName);
        this._handleOffer(remotePeerId, data.sdp);
        break;
      }

      case "answer": {
        const remotePeerId = data.fromPeerId || data.peerId;
        if (data.fromName) this.peerNames.set(remotePeerId, data.fromName);
        this._handleAnswer(remotePeerId, data.sdp);
        break;
      }

      case "ice-candidate": {
        const remotePeerId = data.fromPeerId || data.peerId;
        this._handleIceCandidate(remotePeerId, data.candidate);
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
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
        { urls: "stun:stun2.l.google.com:19302" },
        { urls: "stun:stun.cloudflare.com:3478" },
      ],
    });

    this.peers.set(peerId, pc);

    if (this.localStream) {
      this.localStream.getTracks().forEach((track) => {
        pc.addTrack(track, this.localStream);
      });
    }

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this._send({
          type: "ice-candidate",
          targetPeerId: peerId,
          candidate: event.candidate,
        });
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
        this.onConnectionStateChange(peerId, pc.connectionState);
      }
    };

    pc.oniceconnectionstatechange = () => {
      console.log(`[signaling] Peer ${peerId} iceConnectionState: ${pc.iceConnectionState}`);
      if (pc.iceConnectionState === "failed") {
        pc.restartIce();
      }
    };

    return pc;
  }

  async _flushPendingCandidates(peerId, pc) {
    const queue = this.pendingCandidates.get(peerId);
    if (!queue || queue.length === 0) return;

    this.pendingCandidates.delete(peerId);
    for (const candidate of queue) {
      try {
        await pc.addIceCandidate(new RTCIceCandidate(candidate));
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
        sdp: pc.localDescription,
      });
    } catch (err) {
      console.error("[signaling] Error creating offer:", err);
    }
  }

  async _handleOffer(peerId, sdp) {
    try {
      const pc = this._createPeerConnection(peerId);
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      await this._flushPendingCandidates(peerId, pc);

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      this._send({
        type: "answer",
        targetPeerId: peerId,
        sdp: pc.localDescription,
      });
    } catch (err) {
      console.error("[signaling] Error handling offer:", err);
    }
  }

  async _handleAnswer(peerId, sdp) {
    try {
      const pc = this.peers.get(peerId);
      if (!pc) return;
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      await this._flushPendingCandidates(peerId, pc);
    } catch (err) {
      console.error("[signaling] Error handling answer:", err);
    }
  }

  async _handleIceCandidate(peerId, candidate) {
    if (!candidate) return;
    const pc = this.peers.get(peerId);

    // If the PeerConnection doesn't exist yet or remoteDescription isn't set yet, queue the candidate
    if (!pc || !pc.remoteDescription || !pc.remoteDescription.type) {
      if (!this.pendingCandidates.has(peerId)) {
        this.pendingCandidates.set(peerId, []);
      }
      this.pendingCandidates.get(peerId).push(candidate);
      return;
    }

    try {
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
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
    this.pendingCandidates.delete(peerId);
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