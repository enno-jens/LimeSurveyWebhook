<?php

/**
 * Plain-PHP checks for the webhook payload and signature (no LimeSurvey needed).
 *
 *   php tests/webhook-payload.test.php
 */

require_once __DIR__ . '/../src/WebhookPayload.php';

use Cockpit\LimeSurveyWebhook\WebhookPayload;

function check(bool $ok, string $message): void
{
    if (!$ok) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    echo "ok - {$message}\n";
}

$body = WebhookPayload::body(901, '42', 'abc123');
check(
    $body === '{"surveyId":901,"responseId":"42","token":"abc123"}',
    'body carries only surveyId, responseId and token'
);
check(strpos($body, 'CK_') === false, 'body contains no answers');

$secret = 'shared-secret';
$timestamp = '1761955200';
$signature = WebhookPayload::signature($timestamp, $body, $secret);
check(
    $signature === 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, $secret),
    'signature is HMAC-SHA256 over "<timestamp>.<body>"'
);
check(
    preg_match('/^sha256=[a-f0-9]{64}$/', $signature) === 1,
    'signature has the sha256=<hex> shape the Cockpit expects'
);

$headers = WebhookPayload::headers($timestamp, $signature);
check(in_array('Content-Type: application/json', $headers, true), 'sends JSON');
check(in_array('X-Cockpit-Timestamp: ' . $timestamp, $headers, true), 'sends the timestamp');
check(in_array('X-Cockpit-Signature: ' . $signature, $headers, true), 'sends the signature');

$other = WebhookPayload::signature($timestamp, $body, 'other-secret');
check($other !== $signature, 'a different secret yields a different signature');

echo "all checks passed\n";
