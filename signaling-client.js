class SignalingClient {
  constructor() {
    this.ws = null;
    this.peerId = null;
    this.peers = new Map();
    this.localStream = null;
    this.onRemoteStream = null;
    this.onPeerLeft = null;
    this.onChatMessage = null;
  }

  async connect(roomId, localStream) {
    this.localStream = localStream;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws?room=${encodeURIComponent(roomId)}`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onmessage = (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
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
        console.log(`[signaling] Connected as ${this.peerId}, ${data.peerCount} peer(s) in room`);
        break;
      case "peer-joined":
        this._createOffer(data.peerId);
        break;
      case "peer-left":
        this._removePeer(data.peerId);
        if (this.onPeerLeft) this.onPeerLeft(data.peerId);
        break;
      case "offer":
        this._handleOffer(data.peerId, data.sdp);
        break;
      case "answer":
        this._handleAnswer(data.peerId, data.sdp);
        break;
      case "ice-candidate":
        this._handleIceCandidate(data.peerId, data.candidate);
        break;
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
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });
    this.peers.set(peerId, pc);

    if (this.localStream) {
      this.localStream.getTracks().forEach((track) => {
        pc.addTrack(track, this.localStream);
      });
    }

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this._send({ type: "ice-candidate", peerId, candidate: event.candidate });
      }
    };

    pc.ontrack = (event) => {
      if (this.onRemoteStream) {
        this.onRemoteStream(peerId, event.streams[0]);
      }
    };

    pc.onconnectionstatechange = () => {
      console.log(`[signaling] Peer ${peerId} state: ${pc.connectionState}`);
    };

    return pc;
  }

  async _createOffer(peerId) {
    const pc = this._createPeerConnection(peerId);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this._send({ type: "offer", peerId, sdp: offer });
  }

  async _handleOffer(peerId, sdp) {
    const pc = this._createPeerConnection(peerId);
    await pc.setRemoteDescription(sdp);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    this._send({ type: "answer", peerId, sdp: answer });
  }

  async _handleAnswer(peerId, sdp) {
    const pc = this.peers.get(peerId);
    if (pc) await pc.setRemoteDescription(sdp);
  }

  async _handleIceCandidate(peerId, candidate) {
    const pc = this.peers.get(peerId);
    if (pc) await pc.addIceCandidate(candidate);
  }

  _removePeer(peerId) {
    const pc = this.peers.get(peerId);
    if (pc) { pc.close(); this.peers.delete(peerId); }
  }

  disconnect() {
    if (this.ws) { this.ws.close(); this.ws = null; }
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