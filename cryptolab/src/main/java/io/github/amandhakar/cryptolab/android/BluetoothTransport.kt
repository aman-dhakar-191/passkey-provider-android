package io.github.amandhakar.cryptolab.android

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import io.github.amandhakar.cryptolab.core.Connection
import io.github.amandhakar.cryptolab.core.Listener
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

/**
 * Transport approach 2: Bluetooth Classic RFCOMM, phone to phone with no Wi-Fi needed.
 *
 * The sockets are "insecure" (no Bluetooth pairing or link encryption required) on purpose: like the Wi-Fi
 * network, the Bluetooth link is treated as untrusted, and the secure channel on top provides all the
 * protection. The phones don't have to be paired first; the sender finds the receiver in its paired
 * devices or by scanning (the receiver then makes itself discoverable).
 *
 * Every call here needs the BLUETOOTH_CONNECT permission; the activity requests it before using them.
 */
@SuppressLint("MissingPermission")
object BluetoothTransport {
    /** Identifies Crypto Lab's RFCOMM service (SDP record), so the sender finds the right socket. */
    private val SERVICE_UUID: UUID = UUID.fromString("6f1c3e52-5b0e-4a8e-9a3f-2c7d1b9e4a10")
    private const val SERVICE_NAME = "Crypto Lab"

    val permissions = arrayOf(
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.BLUETOOTH_ADVERTISE,
    )

    fun hasPermissions(context: Context) =
        permissions.all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }

    fun adapter(context: Context): BluetoothAdapter? = context.getSystemService(BluetoothManager::class.java)?.adapter

    /** This phone's Bluetooth name, as other phones see it when scanning. */
    fun name(adapter: BluetoothAdapter): String = adapter.name.orEmpty()

    fun pairedDevices(adapter: BluetoothAdapter): List<BluetoothDevice> = adapter.bondedDevices.orEmpty().toList()

    fun label(device: BluetoothDevice): String = "${device.name ?: "Unnamed"} (${device.address})"

    fun deviceName(device: BluetoothDevice): String? = device.name

    fun isOn(adapter: BluetoothAdapter) = adapter.isEnabled

    /** Finds nearby discoverable phones for about 12 s; results arrive as ACTION_FOUND broadcasts. */
    fun startDiscovery(adapter: BluetoothAdapter) {
        adapter.cancelDiscovery()
        adapter.startDiscovery()
    }

    fun cancelDiscovery(adapter: BluetoothAdapter) {
        adapter.cancelDiscovery()
    }

    /** Asks the person to make this phone visible to unpaired phones for [seconds]. */
    fun discoverableIntent(seconds: Int): Intent =
        Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, seconds)

    class BluetoothListener(adapter: BluetoothAdapter) : Listener {
        private val server: BluetoothServerSocket =
            adapter.listenUsingInsecureRfcommWithServiceRecord(SERVICE_NAME, SERVICE_UUID)

        override fun accept(): Connection = SocketConnection(server.accept())

        override fun close() = server.close()
    }

    fun connect(adapter: BluetoothAdapter, device: BluetoothDevice): Connection {
        // Discovery slows a connection down a lot; it must be off while connecting.
        adapter.cancelDiscovery()
        val socket = device.createInsecureRfcommSocketToServiceRecord(SERVICE_UUID)
        try {
            socket.connect()
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw e
        }
        return SocketConnection(socket)
    }

    private class SocketConnection(private val socket: BluetoothSocket) : Connection {
        override val input: InputStream = BufferedInputStream(socket.inputStream)
        override val output: OutputStream = BufferedOutputStream(socket.outputStream)
        override val peer: String = label(socket.remoteDevice)

        override fun close() = socket.close()
    }
}
