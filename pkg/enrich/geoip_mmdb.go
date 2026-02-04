package enrich

import (
	"context"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type GeoIPMMDB struct {
	db *geoip2.Reader
}

func NewGeoIPMMDB(path string) (*GeoIPMMDB, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &GeoIPMMDB{db: db}, nil
}

func (g *GeoIPMMDB) Lookup(_ context.Context, ip string) (any, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoInfo{}, nil
	}
	record, err := g.db.City(parsed)
	if err != nil {
		return GeoInfo{}, err
	}
	return GeoInfo{
		Country: record.Country.Names["en"],
		City:    record.City.Names["en"],
		Lat:     record.Location.Latitude,
		Lon:     record.Location.Longitude,
	}, nil
}
