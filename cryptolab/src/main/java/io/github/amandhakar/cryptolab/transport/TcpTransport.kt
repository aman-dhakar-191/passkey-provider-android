package io.github.amandhakar.cryptolab.transport

import io.github.amandhakar.cryptolab.core.Connection
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Transport approach 1: plain TCP on the local network (both phones on the same Wi-Fi or hotspot).
 * The network is untrusted; all protection comes from the secure channel on top.
 */
object TcpTransport {
    const val DEFAULT_PORT = 47800

    // Long enough for two people to compare the codes before the first encrypted record.
    private const val READ_TIMEOUT_MS = 5 * 60 * 1000

    class Listener(port: Int = DEFAULT_PORT) : Closeable {
        private val server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(port))
        }

        val port: Int get() = server.localPort

        /** Blocks until a phone connects; [close] from another thread to stop waiting. */
        fun accept(): Connection = SocketConnection(server.accept())

        override fun close() = server.close()
    }

    fun connect(host: String, port: Int = DEFAULT_PORT, timeoutMs: Int = 10_000): Connection {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(host, port), timeoutMs)
        } catch (e: Exception) {
            socket.close()
            throw e
        }
        return SocketConnection(socket)
    }

    private class SocketConnection(private val socket: Socket) : Connection {
        init {
            socket.tcpNoDelay = true
            socket.soTimeout = READ_TIMEOUT_MS
        }

        override val input: InputStream = BufferedInputStream(socket.getInputStream())
        override val output: OutputStream = BufferedOutputStream(socket.getOutputStream())
        override val peer: String = "${socket.inetAddress.hostAddress}:${socket.port}"

        override fun close() = socket.close()
    }
}
