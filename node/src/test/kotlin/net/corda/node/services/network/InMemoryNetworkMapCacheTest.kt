package net.corda.node.services.network

import net.corda.core.getOrThrow
import net.corda.core.node.services.NetworkMapCache
import net.corda.core.node.services.ServiceInfo
import net.corda.testing.ALICE
import net.corda.testing.BOB
import net.corda.testing.node.MockNetwork
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class InMemoryNetworkMapCacheTest {
    lateinit var mockNet: MockNetwork

    @Before
    fun setUp() {
        mockNet = MockNetwork()
    }

    @After
    fun teardown() {
        mockNet.stopNodes()
    }

    @Test
    fun registerWithNetwork() {
        val nodes = mockNet.createSomeNodes(1)
        val n0 = nodes.mapNode
        val n1 = nodes.partyNodes[0]
        val future = n1.services.networkMapCache.addMapService(n1.network, n0.network.myAddress, false, null)
        mockNet.runNetwork()
        future.getOrThrow()
    }

    @Test
    fun `key collision`() {
        val entropy = BigInteger.valueOf(24012017L)
        val nodeA = mockNet.createNode(nodeFactory = MockNetwork.DefaultFactory, legalName = ALICE.name, entropyRoot = entropy, advertisedServices = ServiceInfo(NetworkMapService.type))
        val nodeB = mockNet.createNode(nodeFactory = MockNetwork.DefaultFactory, legalName = BOB.name, entropyRoot = entropy, advertisedServices = ServiceInfo(NetworkMapService.type))
        assertEquals(nodeA.info.legalIdentity, nodeB.info.legalIdentity)

        mockNet.runNetwork()

        // Node A currently knows only about itself, so this returns node A
        assertEquals(nodeA.services.networkMapCache.getNodeByLegalIdentityKey(nodeA.info.legalIdentity.owningKey), nodeA.info)

        nodeA.database.transaction {
            nodeA.services.networkMapCache.addNode(nodeB.info)
        }
        // The details of node B write over those for node A
        assertEquals(nodeA.services.networkMapCache.getNodeByLegalIdentityKey(nodeA.info.legalIdentity.owningKey), nodeB.info)
    }

    @Test
    fun `getNodeByLegalIdentity`() {
        val nodes = mockNet.createSomeNodes(1)
        val n0 = nodes.mapNode
        val n1 = nodes.partyNodes[0]
        val node0Cache: NetworkMapCache = n0.services.networkMapCache
        val expected = n1.info

        mockNet.runNetwork()
        val actual = node0Cache.getNodeByLegalIdentity(n1.info.legalIdentity)
        assertEquals(expected, actual)

        // TODO: Should have a test case with anonymous lookup
    }
}
