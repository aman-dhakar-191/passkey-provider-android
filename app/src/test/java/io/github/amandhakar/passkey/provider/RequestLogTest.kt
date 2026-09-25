package io.github.amandhakar.passkey.provider

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RequestLogTest {
    @Test
    fun githubBuildWritesEveryStep() {
        val log = RequestLog(logEverything = true)
        assertEquals("asked", log.step("asked"))
        assertEquals("signed in", log.succeeded("signed in"))
        assertEquals("failed", log.problem("failed"))
    }

    @Test
    fun storeBuildWritesNothingForASuccessfulRequest() {
        val log = RequestLog(logEverything = false)
        assertNull(log.step("asked by chrome for example.com"))
        assertNull(log.step("user verified"))
        assertNull(log.succeeded("signed in to example.com"))
        // The next problem doesn't carry the successful request's steps.
        assertEquals("failed", log.problem("failed"))
    }

    @Test
    fun storeBuildWritesTheStepsLeadingToAProblem() {
        val log = RequestLog(logEverything = false)
        log.step("asked by chrome for example.com")
        log.step("user verified")
        assertEquals("asked by chrome for example.com\nuser verified\nfailed", log.problem("failed"))
        assertEquals("next", log.problem("next"))
    }

    @Test
    fun heldBackStepsAreCapped() {
        val log = RequestLog(logEverything = false, maxSteps = 2)
        log.step("one")
        log.step("two")
        log.step("three")
        assertEquals("two\nthree\nfailed", log.problem("failed"))
    }
}
