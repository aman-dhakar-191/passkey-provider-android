package io.github.amandhakar.passkey.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class PasskeyStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun passkey(id: String, rp: String = "example.com", user: String = "u1") =
        Passkey(id, rp, "Example", user, "alice", "Alice", createdAt = 1, lastUsedAt = 1)

    @Test fun newPasskeyForSameAccountReplacesTheOldOne() {
        val store = PasskeyStore(File(tmp.root, "p.json"))
        store.add(passkey("a"))
        store.add(passkey("b", user = "u2")) // other account on the same site: kept
        store.add(passkey("c", rp = "other.com")) // same user handle on another site: kept
        val replaced = store.add(passkey("d"))
        assertEquals(listOf("a"), replaced.map { it.credentialId })
        assertEquals(setOf("b", "c", "d"), store.all().map { it.credentialId }.toSet())
    }

    @Test fun persistsRenameMarkUsedAndRemove() {
        val file = File(tmp.root, "p.json")
        PasskeyStore(file).apply {
            add(passkey("a"))
            add(passkey("b", user = "u2"))
            rename("a", "  Work laptop  ")
            markUsed("a", 42)
            remove("b")
        }
        val reloaded = PasskeyStore(file).all()
        assertEquals(1, reloaded.size)
        assertEquals("Work laptop", reloaded[0].label)
        assertEquals(42L, reloaded[0].lastUsedAt)
    }

    @Test fun unreadableFileIsKeptAsideNotOverwritten() {
        val file = File(tmp.root, "p.json").apply { writeText("{broken") }
        val store = PasskeyStore(file)
        assertTrue(store.all().isEmpty())
        store.add(passkey("a"))
        val kept = tmp.root.listFiles()!!.filter { it.name.startsWith("p.json.unreadable-") }
        assertEquals(1, kept.size)
        assertEquals("{broken", kept[0].readText())
    }

    @Test fun oldFilesWithoutLabelStillLoad() {
        val file = File(tmp.root, "p.json")
        file.writeText(
            """[{"credentialId":"a","rpId":"example.com","rpName":"E","userId":"u","userName":"n",
               "displayName":"d","createdAt":1,"lastUsedAt":2}]""",
        )
        assertEquals("", PasskeyStore(file).all().single().label)
    }
}
