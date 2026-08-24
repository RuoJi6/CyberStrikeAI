package egress

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSLeaseStore links policy-approved DNS answers to the L3/L4 packet path.
// A direct-IP packet cannot borrow a hostname rule unless that exact address
// was returned for the hostname and its DNS TTL is still active.
type DNSLeaseStore struct {
	mu      sync.Mutex
	byIP    map[netip.Addr]map[string]time.Time
	maximum int
}

const maxDNSLeases = 4096

func NewDNSLeaseStore() *DNSLeaseStore {
	return &DNSLeaseStore{byIP: make(map[netip.Addr]map[string]time.Time), maximum: maxDNSLeases}
}

func (s *DNSLeaseStore) Remember(domain string, addresses []netip.Addr, ttl uint32, now time.Time) {
	if s == nil || ttl == 0 {
		return
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return
	}
	expiresAt := now.UTC().Add(time.Duration(ttl) * time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now.UTC())
	for _, raw := range addresses {
		address := raw.Unmap()
		if !address.IsValid() || address.Zone() != "" {
			continue
		}
		if s.countLocked() >= s.maximum {
			return
		}
		domains := s.byIP[address]
		if domains == nil {
			domains = make(map[string]time.Time)
			s.byIP[address] = domains
		}
		if current := domains[domain]; current.Before(expiresAt) {
			domains[domain] = expiresAt
		}
	}
}

func (s *DNSLeaseStore) Domains(address netip.Addr, now time.Time) []string {
	if s == nil {
		return nil
	}
	address = address.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now.UTC())
	domains := s.byIP[address]
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result
}

func (s *DNSLeaseStore) pruneLocked(now time.Time) {
	for address, domains := range s.byIP {
		for domain, expiresAt := range domains {
			if !now.Before(expiresAt) {
				delete(domains, domain)
			}
		}
		if len(domains) == 0 {
			delete(s.byIP, address)
		}
	}
}

func (s *DNSLeaseStore) countLocked() int {
	count := 0
	for _, domains := range s.byIP {
		count += len(domains)
	}
	return count
}
