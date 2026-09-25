package io.github.amandhakar.passkey.data

/** Passkeys for one website (RP ID), as shown under one heading in the list. */
data class SiteGroup(val rpId: String, val title: String, val passkeys: List<Passkey>)

object PasskeyGroups {
    /**
     * Filters by [query] (site, site name, user name, display name or label; case-insensitive) and groups
     * by site. Sites are sorted by title, passkeys within a site by most recently used.
     */
    fun of(passkeys: List<Passkey>, query: String): List<SiteGroup> {
        val q = query.trim().lowercase()
        return passkeys
            .filter { p ->
                q.isEmpty() || listOf(p.rpId, p.rpName, p.userName, p.displayName, p.label)
                    .any { it.lowercase().contains(q) }
            }
            .groupBy { it.rpId }
            .map { (rpId, list) ->
                val name = list.firstNotNullOfOrNull { it.rpName.takeIf { n -> n.isNotBlank() && n != rpId } }
                SiteGroup(rpId, name ?: rpId, list.sortedByDescending { it.lastUsedAt })
            }
            .sortedWith(compareBy({ it.title.lowercase() }, { it.rpId }))
    }
}
