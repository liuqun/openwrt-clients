#ifndef URL_H
#define URL_H

#ifdef __cplusplus
extern "C" {
#endif

        //int php_url_decode(char *str, int len);
char *php_url_encode(char const *s, int len, int *new_length);

#ifdef __cplusplus
}
#endif

#endif /* URL_H */
