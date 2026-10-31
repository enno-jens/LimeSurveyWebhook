<?php

/**
 * Payload and signature of the Cockpit webhook (spec 014).
 *
 * The body carries only the survey id, the response id and the participant token –
 * never answers. The signature is HMAC-SHA256 over "<timestamp>.<body>" and travels
 * in `X-Cockpit-Signature: sha256=<hex>` next to `X-Cockpit-Timestamp`.
 *
 * Kept free of LimeSurvey classes so it can be tested with a plain PHP binary.
 */

namespace Cockpit\LimeSurveyWebhook;

class WebhookPayload
{
    public static function body(int $surveyId, string $responseId, string $token): string
    {
        return json_encode(
            [
                'surveyId' => $surveyId,
                'responseId' => $responseId,
                'token' => $token,
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }

    public static function signature(string $timestamp, string $body, string $secret): string
    {
        return 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, $secret);
    }

    /** @return string[] */
    public static function headers(string $timestamp, string $signature): array
    {
        return [
            'Content-Type: application/json',
            'X-Cockpit-Timestamp: ' . $timestamp,
            'X-Cockpit-Signature: ' . $signature,
        ];
    }
}
