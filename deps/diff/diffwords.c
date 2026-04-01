/*
 * Copyright (c) 2018 Kristaps Dzonsons <kristaps@bsd.lv>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "config.h"

#ifdef HAVE_ERR
# include <err.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diff.h"

static int
word_cmp(const void *p1, const void *p2)
{

	return 0 == strcmp(*(const char **)p1, *(const char **)p2);
}

static void
tokenise(char *input, char ***out, size_t *outsz)
{
	char	*cp;

	while (NULL != (cp = strsep(&input, " "))) {
		if ('\0' == *cp)
			continue;
		*out = reallocarray
			(*out, *outsz + 1, sizeof(char *));
		if (NULL == *out)
			err(EXIT_FAILURE, NULL);
		(*out)[*outsz] = cp;
		(*outsz)++;
	}
}

int 
main(int argc, char *argv[]) 
{
	size_t	 	  i;
	int		  rc;
	struct diff	  p;
	char		**origin = NULL, **target = NULL;
	size_t		  originsz = 0, targetsz = 0;

	if (argc < 3) {
		fprintf(stderr, "usage: %s origin target\n", 
			getprogname());
		return EXIT_FAILURE;
	}

	tokenise(argv[1], &origin, &originsz);
	tokenise(argv[2], &target, &targetsz);

	rc = diff(&p, word_cmp, sizeof(char *), 
		origin, originsz,
		target, targetsz);

	if (rc < 0)
		err(EXIT_FAILURE, NULL);
	if (0 == rc)
		errx(EXIT_FAILURE, "cannot compute difference");

	puts("Shortest edit script:");
	for (i = 0; i < p.sessz; i++)
		printf("%s%s\n",
			DIFF_ADD == p.ses[i].type ?  "+" :
			DIFF_DELETE == p.ses[i].type ?  "-" : " ",
			*(const char **)p.ses[i].e);

	puts("Longest common subsequence:");
	for (i = 0; i < p.lcssz; i++)
		printf(" %s\n", *(const char **)p.lcs[i]);

	printf("Edit distance: %zu\n", p.editdist);

	free(p.ses);
	free(p.lcs);
	free(origin);
	free(target);
	return EXIT_SUCCESS;
}
