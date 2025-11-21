<!-- module github.com/Ajay263/ecs_rds_terraform

go 1.24.2

require (
	github.com/gorilla/sessions v1.4.0
	github.com/lib/pq v1.10.9
	golang.org/x/oauth2 v0.29.0
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
) -->























// go.mod - WITH INTENTIONAL VULNERABILITIES FOR TESTING
module github.com/Ajay263/ecs_rds_terraform

go 1.24.2

require (
	// Vulnerable version - has CVE-2025-24358 CSRF vulnerability
	github.com/gorilla/csrf v1.7.2
	
	// Vulnerable version - old JWT library with "None" algorithm issue
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	
	// Keep your existing dependencies
	github.com/gorilla/sessions v1.4.0
	github.com/lib/pq v1.10.9
	
	// Older version that may have vulnerabilities
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	
	// Old crypto package version
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	
	// Vulnerable version with HTTP/2 rapid reset attack
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)