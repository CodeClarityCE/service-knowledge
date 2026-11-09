package pgsql

import (
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/sirupsen/logrus"
)

var dateLogger = sourcesync.NewLogger()

// Formats seen in upstream data. Values with no offset are read as UTC.
var timestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02",
}

// NormalizeTimestamp returns raw as RFC 3339 in UTC. It reports false when raw is not a date.
func NormalizeTimestamp(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	for _, layout := range timestampLayouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), true
		}
	}
	return "", false
}

// normalizeDate rewrites one date field, or clears it with a warning if it is not a date.
func normalizeDate(table, recordID, column string, value *string) {
	normalized, ok := NormalizeTimestamp(*value)
	if !ok {
		dateLogger.WithFields(logrus.Fields{"table": table, "record_id": recordID, "column": column, "raw_value": *value}).
			Warn("Dropping unparseable knowledge date")
	}
	*value = normalized
}

func normalizeOsvDates(items []knowledge.OSVItem) {
	for i := range items {
		item := &items[i]
		wasWithdrawn := item.Withdrawn != ""
		normalizeDate("osv", item.OSVId, "modified", &item.Modified)
		normalizeDate("osv", item.OSVId, "published", &item.Published)
		normalizeDate("osv", item.OSVId, "withdrawn", &item.Withdrawn)
		// A withdrawn advisory with a bad date is still withdrawn.
		if wasWithdrawn && item.Withdrawn == "" {
			item.Withdrawn = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
}

func normalizeNvdDates(items []knowledge.NVDItem) {
	for i := range items {
		normalizeDate("nvd", items[i].NVDId, "published", &items[i].Published)
		normalizeDate("nvd", items[i].NVDId, "lastModified", &items[i].LastModified)
	}
}

func normalizeGcveDates(items []knowledge.GCVEItem) {
	for i := range items {
		normalizeDate("gcve", items[i].GCVEId, "date_published", &items[i].DatePublished)
		normalizeDate("gcve", items[i].GCVEId, "date_updated", &items[i].DateUpdated)
	}
}

func normalizeFriendsOfPhpDates(items []knowledge.FriendsOfPHPAdvisory) {
	for i := range items {
		normalizeDate("friends_of_php", items[i].AdvisoryId, "published", &items[i].Published)
		normalizeDate("friends_of_php", items[i].AdvisoryId, "modified", &items[i].Modified)
	}
}
