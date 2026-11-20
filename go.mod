module github.com/towerops-app/towerops-agent

go 1.27.3

require (
	github.com/coder/websocket v1.8.15
	github.com/gosnmp/gosnmp v1.47.0
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.50.0
	google.golang.org/protobuf v1.36.12
	pgregory.net/rapid v1.3.0
)

// The modern protobuf module still lists this unused legacy graph dependency.
// Exclude it rather than adding a package import solely to retain an upgrade.
exclude github.com/golang/protobuf v1.5.0
