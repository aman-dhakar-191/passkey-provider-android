package io.github.amandhakar.passkey.data

import org.junit.Assert.assertEquals
import org.junit.Test

class PasskeyGroupsTest {
    private fun p(id: String, rp: String, rpName: String = "", user: String = "u", used: Long = 0, label: String = "") =
        Passkey(id, rp, rpName, "uid", user, "", createdAt = 0, lastUsedAt = used, label = label)

    private val all = listOf(
        p("1", "b.example.com", "Bravo", user = "alice", used = 1),
        p("2", "b.example.com", "Bravo", user = "bob", used = 5, label = "Work"),
        p("3", "a.example.com", user = "carol"),
        p("4", "zeta.org", "Alpha Corp"),
    )

    @Test fun groupsBySiteSortedByTitleThenMostRecent() {
        val groups = PasskeyGroups.of(all, "")
        assertEquals(listOf("a.example.com", "Alpha Corp", "Bravo"), groups.map { it.title })
        assertEquals(listOf("2", "1"), groups[2].passkeys.map { it.credentialId })
    }

    @Test fun searchMatchesSiteUserAndLabelIgnoringCase() {
        assertEquals(listOf("2"), PasskeyGroups.of(all, "work").flatMap { g -> g.passkeys.map { it.credentialId } })
        assertEquals(listOf("3"), PasskeyGroups.of(all, "CAROL").flatMap { g -> g.passkeys.map { it.credentialId } })
        assertEquals(listOf("4"), PasskeyGroups.of(all, "zeta").flatMap { g -> g.passkeys.map { it.credentialId } })
        assertEquals(emptyList<SiteGroup>(), PasskeyGroups.of(all, "nothing"))
    }
}
