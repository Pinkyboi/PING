/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abenaiss <abenaiss@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/10 21:28:57 by abenaiss          #+#    #+#             */
/*   Updated: 2023/02/14 10:13:53 by abenaiss         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

char	*ft_strtrim(char const *s)
{
	size_t	i;
	size_t	len_s;
	char	*t;

	if (!s)
		return (NULL);
	i = 0;
	len_s = ft_strlen(s);
	while (*s && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t'))
		i++;
	while (len_s - 1 != 0 && (s[len_s - 1] == ' '
		|| s[len_s - 1] == '\n' || s[len_s - 1] == '\t'))
		len_s--;
	if ((len_s - 1 == 0 || i == len_s))
	{
		t = (char*)malloc(sizeof(char));
		*t = '\0';
		return (t);
	}
	t = ft_strsub(s, i, len_s - i);
	return (t);
}
