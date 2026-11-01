module github.com/towerops-app/towerops-agent

go 1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/gosnmp/gosnmp v1.46.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	google.golang.org/protobuf v1.36.12
	pgregory.net/rapid v1.3.0
)

require golang.org/x/sys v0.49.0 // indirect

// The modern protobuf module still lists this unused legacy graph dependency.
// Exclude it rather than adding a package import solely to retain an upgrade.
exclude github.com/golang/protobuf v1.5.0
