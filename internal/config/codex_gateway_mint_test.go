package config

import "testing"

func TestGatewayMintConfigValidation(t *testing.T) {
	for _, mutate := range []func(*CodexTurnTicketSettings){
		func(c *CodexTurnTicketSettings) { c.MintMaxAttempts = 129 },
		func(c *CodexTurnTicketSettings) { c.MintTotalTimeoutSeconds = 181 },
		func(c *CodexTurnTicketSettings) { c.MintTicketTTLSeconds = -1 },
		func(c *CodexTurnTicketSettings) { c.MintWorkers = 33 },
		func(c *CodexTurnTicketSettings) { c.MintTransports = []string{"typo"} },
		func(c *CodexTurnTicketSettings) { c.MintTransports = []string{} },
		func(c *CodexTurnTicketSettings) { c.MintGateway = "unified-88\r\n" },
		func(c *CodexTurnTicketSettings) { c.MintRejectGateways = []string{""} },
		func(c *CodexTurnTicketSettings) { c.MintRejectGateways = []string{"any"} },
		func(c *CodexTurnTicketSettings) { c.MintRejectGateways = []string{"unified-149\r\n"} },
		func(c *CodexTurnTicketSettings) { c.MintRejectGateways = []string{"not-a-gateway"} },
	} {
		c := CodexTurnTicketSettings{}
		mutate(&c)
		if c.Validate() == nil {
			t.Fatalf("invalid settings accepted: %+v", c)
		}
	}
	c := CodexTurnTicketSettings{}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.MintGateway = "any"
	c.MintRejectGateways = []string{"unified-149"}
	c.MintTransports = []string{"sse", "websocket"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
