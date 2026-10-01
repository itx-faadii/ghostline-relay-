import unittest

from relay_broker import RelayBroker


class RelayBrokerTests(unittest.TestCase):
    def test_publish_relays_payload_to_all_subscribers(self) -> None:
        broker = RelayBroker()
        received = []

        broker.subscribe("alerts", lambda message: received.append(("a", message)))
        broker.subscribe("alerts", lambda message: received.append(("b", message)))

        delivered = broker.publish("alerts", {"status": "ok"})

        self.assertEqual(delivered, 2)
        self.assertEqual(
            received,
            [("a", {"status": "ok"}), ("b", {"status": "ok"})],
        )

    def test_unsubscribe_removes_handler(self) -> None:
        broker = RelayBroker()
        received = []

        def handler(message):
            received.append(message)

        broker.subscribe("alerts", handler)
        removed = broker.unsubscribe("alerts", handler)
        delivered = broker.publish("alerts", "message")

        self.assertTrue(removed)
        self.assertEqual(delivered, 0)
        self.assertEqual(received, [])

    def test_subscribe_requires_callable_handler(self) -> None:
        broker = RelayBroker()

        with self.assertRaises(TypeError):
            broker.subscribe("alerts", "not-callable")


if __name__ == "__main__":
    unittest.main()
