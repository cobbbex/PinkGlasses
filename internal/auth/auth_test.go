package auth

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("a passphrase for the tests")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(h, "a passphrase for the tests")
	if err != nil || !ok {
		t.Fatalf("correct password rejected: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword(h, "correct horse battery stapl")
	if ok {
		t.Error("wrong password accepted")
	}
	// Two hashes of the same password must differ: a shared salt would make
	// the table tell you which accounts share a password.
	h2, _ := HashPassword("a passphrase for the tests")
	if h == h2 {
		t.Error("hashes are not salted")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext", "$argon2id$v=19$m=1,t=1,p=1$short",
		"$bcrypt$v=19$m=65536,t=3,p=4$c2FsdA$a2V5",   // right shape, wrong algorithm
		"$argon2id$v=13$m=65536,t=3,p=4$c2FsdA$a2V5", // wrong version
	} {
		if ok, err := VerifyPassword(bad, "anything"); ok || err == nil {
			t.Errorf("malformed hash %q: ok=%v err=%v (must fail closed)", bad, ok, err)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := CheckPasswordPolicy("short"); err == nil {
		t.Error("an 5-character password was accepted")
	}
	if err := CheckPasswordPolicy("twelve chars"); err != nil {
		t.Errorf("a 12-character password was rejected: %v", err)
	}
	// Unbounded input would make the server do unbounded argon2 work.
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'a'
	}
	if err := CheckPasswordPolicy(string(long)); err == nil {
		t.Error("an oversized password was accepted")
	}
}

func TestRoleOrdering(t *testing.T) {
	cases := []struct {
		have, min Role
		want      bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleAdmin, false},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleViewer, true},
		// An unrecognised role must grant nothing, not everything. A typo in
		// the database, or a role added later and deployed unevenly, has to
		// fail closed.
		{Role("superuser"), RoleViewer, false},
		{Role(""), RoleViewer, false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.min); got != c.want {
			t.Errorf("Role(%q).AtLeast(%q) = %v, want %v", c.have, c.min, got, c.want)
		}
	}
}

func TestSecretsAreDistinctAndHashed(t *testing.T) {
	a, ha, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := NewSecret()
	if a == b {
		t.Fatal("two secrets came out the same")
	}
	if string(ha) == a {
		t.Fatal("the stored form is the secret itself")
	}
	if string(HashSecret(a)) != string(ha) {
		t.Fatal("HashSecret does not agree with NewSecret")
	}
}

// The generated first-boot password must satisfy the policy every user is held
// to, and two generations must differ.
func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPasswordPolicy(a); err != nil {
		t.Errorf("generated password %q fails the policy: %v", a, err)
	}
	b, _ := GeneratePassword()
	if a == b {
		t.Error("two generated passwords were identical")
	}
}

func TestDefaultAdminPassword(t *testing.T) {
	t.Setenv("ASM_DEFAULT_ADMIN_PASSWORD", "")
	if got := DefaultAdminPassword(); got != "" {
		t.Errorf("unset must mean generate (empty), got %q", got)
	}
	if SeedDisabled() {
		t.Error("unset must not disable seeding")
	}
	t.Setenv("ASM_DEFAULT_ADMIN_PASSWORD", "a chosen passphrase")
	if got := DefaultAdminPassword(); got != "a chosen passphrase" {
		t.Errorf("override ignored: got %q", got)
	}
	t.Setenv("ASM_DEFAULT_ADMIN_PASSWORD", "-")
	if !SeedDisabled() || DefaultAdminPassword() != "" {
		t.Error(`"-" must disable seeding entirely`)
	}
}
