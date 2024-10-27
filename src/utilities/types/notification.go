package types

type NotificationType string

type NotificationContentType string

const (
	Info    NotificationType = "info"
	Warning NotificationType = "warning"
	Error   NotificationType = "error"
)

const (
	NewVersion NotificationContentType = "new_version"
)

type Notification struct {
	Key         string                  `json:"_key"`
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	Content     map[string]string       `json:"content"`
	Type        NotificationType        `json:"type"`
	ContentType NotificationContentType `json:"content_type"`
}
