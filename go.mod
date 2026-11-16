module github.com/lczyk/chisel-elftree

go 1.26.0

require (
	github.com/canonical/chisel v1.5.1
	github.com/jessevdk/go-flags v1.6.1
	github.com/klauspost/compress v1.18.0
	github.com/lczyk/chisel-coverage/pkg v0.9.0
	github.com/lczyk/chisel-elftree/pkg v0.0.0-00010101000000-000000000000
	github.com/lczyk/chisel-proxy/pkg v0.5.0
	github.com/lczyk/version/go v0.6.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/blakesmith/ar v0.0.0-20190502131153-809d4375e1fb // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/lczyk/chisel-elftree/pkg => ./pkg
