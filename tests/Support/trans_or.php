<?php

declare(strict_types=1);

/*
 * `trans_or()` is the I18n plugin's helper, and this plugin's own vendor tree
 * does not install I18n. The filter only calls it to word a refusal, so the
 * tests get its documented fallback behaviour: the default string, verbatim.
 */
if (!function_exists('trans_or')) {
    function trans_or(string $key, string $default, array $replace = [], ?string $locale = null): string
    {
        return $default;
    }
}
