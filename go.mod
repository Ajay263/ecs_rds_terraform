module github.com/Ajay263/ecs_rds_terraform

go 1.24.2

require (
	github.com/gorilla/sessions v1.4.0
	github.com/lib/pq v1.10.9
	golang.org/x/oauth2 v0.29.0
	// Vulnerable packages added for testing SCA:
	golang.org/x/net v0.7.0        // CVE-2023-44487, CVE-2023-3978 - Multiple vulnerabilities
	golang.org/x/text v0.3.0       // CVE-2020-14040 - Known vulnerability
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2  // Old version with vulnerabilities
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
)