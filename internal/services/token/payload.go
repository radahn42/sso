package token

type Payload struct {
	UserID int64
	Email  string
	AppID  int
	Roles  []string
	Secret string
}
