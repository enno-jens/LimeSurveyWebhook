<?php

/***** ***** ***** ***** *****
* Sends a signed webhook after each afterSurveyComplete event.
*
* Fork of IrishWolf/LimeSurveyWebhook, hardened for the Cockpit (spec 014):
* TLS verification on, HMAC-SHA256 with timestamp, JSON, timeout, no debug output
* and no answers in the payload or the log.
*
* @originalauthor Stefan Verweij <stefan@evently.nl>
* @copyright 2016 Evently <https://www.evently.nl>
* @author IrishWolf
* @copyright 2023 Nerds Go Casual e.V.
* @license GPL-3.0-or-later
* @version 2.0.0
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
***** ***** ***** ***** *****/

require_once __DIR__ . '/src/WebhookPayload.php';

use Cockpit\LimeSurveyWebhook\WebhookPayload;

class LimeSurveyWebhook extends PluginBase
{
    protected $storage = 'DbStorage';
    static protected $description = 'Signed webhook for the Cockpit after a survey is completed';
    static protected $name = 'LimeSurveyWebhook';

    /** Seconds the Cockpit accepts a timestamp; keep both sides in sync. */
    private const TIMEOUT_SECONDS = 5;

    public function init()
    {
        $this->subscribe('afterSurveyComplete');
    }

    protected $settings = [
        'sUrl' => [
            'type' => 'string',
            'label' => 'Webhook URL',
            'help' => 'https://<cockpit-domain>/api/webhooks/limesurvey – only HTTPS is sent to.',
        ],
        'sId' => [
            'type' => 'string',
            'default' => '',
            'label' => 'Survey IDs',
            'help' => 'Comma-separated survey ids this webhook fires for, e.g. 123456,234567. Empty = every survey.',
        ],
        'sSecret' => [
            'type' => 'string',
            'label' => 'Webhook secret',
            'help' => 'Shared secret for the HMAC signature (LIMESURVEY_WEBHOOK_SECRET in the Cockpit).',
        ],
    ];

    public function afterSurveyComplete()
    {
        $event = $this->getEvent();
        $surveyId = (int) $event->get('surveyId');
        $configured = (string) $this->get('sId', null, null, '');
        $ids = array_filter(array_map('trim', explode(',', $configured)));

        if ($ids && !in_array((string) $surveyId, $ids, true)) {
            return;
        }

        $this->callWebhook($surveyId, (string) $event->get('responseId'));
    }

    private function callWebhook(int $surveyId, string $responseId): void
    {
        $url = trim((string) $this->get('sUrl', null, null, ''));
        $secret = trim((string) $this->get('sSecret', null, null, ''));

        if ($secret === '') {
            $this->log('LimeSurveyWebhook: no secret configured, nothing sent');
            return;
        }
        if (!preg_match('#^https://#i', $url)) {
            $this->log('LimeSurveyWebhook: URL is missing or not HTTPS, nothing sent');
            return;
        }

        $token = $this->participantToken($surveyId, $responseId);
        if ($token === null) {
            // Without the token the Cockpit cannot match the participant; do not send answers instead.
            $this->log('LimeSurveyWebhook: no participant token for survey ' . $surveyId . ', nothing sent');
            return;
        }

        $timestamp = (string) time();
        $body = WebhookPayload::body($surveyId, $responseId, $token);
        $signature = WebhookPayload::signature($timestamp, $body, $secret);

        $handle = curl_init();
        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => WebhookPayload::headers($timestamp, $signature),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            // Answers and tokens only travel over a verified TLS connection.
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT_SECONDS,
            CURLOPT_TIMEOUT => self::TIMEOUT_SECONDS,
            CURLOPT_FOLLOWLOCATION => false,
        ]);

        curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);

        // Log the outcome only: no body, no token, no answers.
        if ($error !== '' || $status >= 300) {
            $this->log(
                'LimeSurveyWebhook: delivery failed for survey ' . $surveyId .
                ' (HTTP ' . $status . ($error !== '' ? ', ' . $error : '') . ')'
            );
        }
    }

    /** Reads the participant token of one response; answers stay untouched. */
    private function participantToken(int $surveyId, string $responseId): ?string
    {
        $table = $this->pluginManager->getAPI()->getResponseTable($surveyId);
        if (!$table) {
            return null;
        }
        $token = Yii::app()->db->createCommand()
            ->select('token')
            ->from($table)
            ->where('id = :id', [':id' => $responseId])
            ->queryScalar();

        return is_string($token) && $token !== '' ? $token : null;
    }
}
