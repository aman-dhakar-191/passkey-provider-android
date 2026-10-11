package io.github.amandhakar.securechannel

import java.net.Inet4Address
import java.net.NetworkInterface

/** This phone's addresses that another phone nearby can reach over TCP. */
object LocalNetwork {
    /** Wi-Fi, hotspot, Wi-Fi Direct and Ethernet interfaces. */
    private val LOCAL_INTERFACES = listOf("wlan", "swlan", "ap", "p2p", "eth")

    /** Mobile-data interfaces (Qualcomm, MediaTek): never reachable from the other phone. */
    private val MOBILE_INTERFACES = listOf("rmnet", "ccmni", "v4-rmnet", "v4-ccmni")

    fun isLocalNetwork(iface: String) = LOCAL_INTERFACES.any { iface.startsWith(it) }

    /**
     * IPv4 addresses with their interface name, Wi-Fi and hotspot first. Others (VPN tunnels, a carrier's
     * 100.x address) come last; they are rarely reachable from the other phone.
     */
    fun addresses(): List<Pair<String, String>> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { nif -> nif.isUp && !nif.isLoopback && MOBILE_INTERFACES.none { nif.name.startsWith(it) } }
            .flatMap { nif ->
                nif.inetAddresses.toList().filterIsInstance<Inet4Address>().map { it.hostAddress.orEmpty() to nif.name }
            }
            .filter { it.first.isNotEmpty() }
            .sortedBy { if (isLocalNetwork(it.second)) 0 else 1 }
    }.getOrDefault(emptyList())

    /** "host:port" targets for an invite: the local-network addresses, or every address if there are none. */
    fun inviteTargets(port: Int): List<String> {
        val all = addresses()
        return all.filter { isLocalNetwork(it.second) }.ifEmpty { all }.map { "${it.first}:$port" }
    }
}
