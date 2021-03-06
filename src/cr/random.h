#include<gcrypt.h>

void cr_random_fill(const size_t buffer_len, unsigned char **buffer);
void cr_random_fill_with_nums_chars(const size_t buffer_len, unsigned char **buffer);
size_t cr_random_fill_with_nums_chars_in_range(const ssize_t min,
					       const ssize_t max,
					       unsigned char **buffer,
					       size_t *buffer_len);
size_t cr_random_number_256(const size_t min, const size_t max);
