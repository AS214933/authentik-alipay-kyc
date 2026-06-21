package crypto

import "testing"

func TestNormalizeIDNumber(t *testing.T) {
	got := NormalizeIDNumber(" 110105-1949 1231 00x ")
	want := "1101051949123100X"
	if got != want {
		t.Fatalf("NormalizeIDNumber() = %q, want %q", got, want)
	}
}

func TestIDHashUsesPepper(t *testing.T) {
	id := "11010519491231002X"
	a := IDHash(id, "pepper-a")
	b := IDHash(id, "pepper-b")
	if a == b {
		t.Fatal("IDHash should change when the pepper changes")
	}
	if len(a) != 64 {
		t.Fatalf("IDHash length = %d, want 64", len(a))
	}
}

func TestLast4(t *testing.T) {
	got := Last4("11010519491231002x")
	if got != "002X" {
		t.Fatalf("Last4() = %q, want %q", got, "002X")
	}
}

func TestMaskChineseName(t *testing.T) {
	cases := map[string]string{
		"张三":   "*三",
		"欧阳娜娜": "***娜",
		"李":    "李",
	}
	for in, want := range cases {
		if got := MaskChineseName(in); got != want {
			t.Fatalf("MaskChineseName(%q) = %q, want %q", in, got, want)
		}
	}
}
