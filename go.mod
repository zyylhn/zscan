module zscan

go 1.16

require (
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/denisenkom/go-mssqldb v0.11.0
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-redis/redis/v8 v8.11.5
	github.com/go-sql-driver/mysql v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/cel-go v0.4.2
	github.com/google/gopacket v1.1.19
	github.com/gookit/color v1.5.0
	github.com/gosnmp/gosnmp v1.34.0
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358 // indirect
	github.com/jlaffaye/ftp v0.0.0-20211117213618-11820403398b
	github.com/lib/pq v1.10.4
	github.com/malfunkt/iprange v0.9.0
	github.com/projectdiscovery/cdncheck v0.0.3
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca
	github.com/spf13/cobra v1.2.1
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	github.com/tomatome/grdp v0.0.0-20211016064301-f2f15c171086
	github.com/zyylhn/redis_rce v0.1.1
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871
	golang.org/x/net v0.0.0-20211118161319-6a13c67c3ce4
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad // indirect
	golang.org/x/text v0.3.7
	google.golang.org/genproto v0.0.0-20210831024726-fe130286e0e2
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/tomatome/grdp v0.0.0-20211016064301-f2f15c171086 => github.com/shadow1ng/grdp v1.0.3
