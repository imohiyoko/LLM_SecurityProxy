package field

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"userName":       "user name",
		"user_name":      "user name",
		"user-name":      "user name",
		"USER_NAME":      "user name",
		"user.name":      "user name",
		"User Name":      "user name",
		"UserName":       "user name",
		"__user__name__": "user name",
		"displayName":    "display name",
		"XMLName":        "xml name",
		"userID":         "user id",
		"userIDNumber":   "user id number",
		"address1":       "address1",
		"user2Name":      "user2 name",
		"名前":             "名前",
		"ユーザー_名":         "ユーザー 名",
		"":               "",
		"__":             "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeySet(t *testing.T) {
	ks, err := NewKeySet([]string{"user_name", "displayName", "full name"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"userName", "user_name", "user-name", "USER_NAME", "user.name", "UserName",
		"display_name", "DISPLAY-NAME", "fullName", "full_name",
		"self.user_name", "profile.displayName", "a.b.FULL_NAME",
		"username", "USERNAME", "displayname", "DISPLAYNAME", "fullname",
	} {
		if !ks.Match(name) {
			t.Errorf("Match(%q) = false", name)
		}
	}
	for _, name := range []string{
		"name", "user", "billing_user_name", "billingusername", "userNameKana",
		"user_name_length", "display", "user.name.kana", "",
	} {
		if ks.Match(name) {
			t.Errorf("Match(%q) = true", name)
		}
	}
}

func TestNewKeySetRejectsEmpty(t *testing.T) {
	if _, err := NewKeySet([]string{"user_name", "--"}); err == nil {
		t.Error("key without letters accepted")
	}
	if _, err := NewKeySet(nil); err == nil {
		t.Error("empty key set accepted")
	}
}
