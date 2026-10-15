package handlers

import "github.com/babykart/gozone/internal/dnsops"

// zoneLocks aliases the shared per-zone locker that lives in the dnsops
// service layer. The Handler holds a pointer to the service's instance so
// REST, web and (later) MCP record writes on the same zone serialize
// against each other. See dnsops.ZoneLocks for the rationale.
type zoneLocks = dnsops.ZoneLocks
