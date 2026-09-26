package io.github.amandhakar.passkey.provider

/**
 * Decides what reaches the activity log. With [logEverything] (GitHub builds) every step is written. Otherwise
 * (store builds) the steps of the current request are only held in memory and written together with a problem,
 * so the log explains failures without keeping a history of successful sign-ins.
 */
class RequestLog(private val logEverything: Boolean, private val maxSteps: Int = 20) {
    private val steps = ArrayDeque<String>()

    /** A step of a request. Returns the entry to write now, or null if it is held back. */
    @Synchronized
    fun step(message: String): String? {
        if (logEverything) return message
        steps.addLast(message)
        while (steps.size > maxSteps) steps.removeFirst()
        return null
    }

    /** Something went wrong: returns the entry to write, including the held-back steps that led to it. */
    @Synchronized
    fun problem(message: String): String {
        val entry = (steps + message).joinToString("\n")
        steps.clear()
        return entry
    }

    /** The request succeeded. Returns the entry to write, or null if successes aren't logged. */
    @Synchronized
    fun succeeded(message: String): String? {
        steps.clear()
        return if (logEverything) message else null
    }
}
