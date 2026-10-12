/* Compile only. Never run this artifact. */
extern int external_dependency(int);
const char rea_fixture_label[] = "REA ELF layout fixture";
int rea_fixture_add(int left, int right) { return left + right; }
int rea_fixture_call(int value) { return external_dependency(value); }
