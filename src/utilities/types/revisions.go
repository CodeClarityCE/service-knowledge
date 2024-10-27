package types

type Revision struct {
	Revision    string `json:"revision"`
	OldRevision string `json:"old_revision"`
	Id          string `json:"id"`
	Data        any    `json:"data"`
}
