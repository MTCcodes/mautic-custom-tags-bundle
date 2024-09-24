<?php

/*
 * @copyright   2016 Mautic Contributors. All rights reserved
 * @author      Mautic
 *
 * @link        http://mautic.org
 *
 * @license     GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 */

namespace MauticPlugin\MauticCustomTagsBundle\Helper;

use GuzzleHttp\Client;
use Mautic\LeadBundle\Entity\Lead;
use Mautic\LeadBundle\Helper\PrimaryCompanyHelper;

/**
 * Class TokenHelper.
 */
class TokenHelper
{
    /**
     * @var Client
     */
    protected $connector;

    /**
     * @var PrimaryCompanyHelper
     */
    private $primaryCompanyHelper;

    /**
     * TokenHelper constructor.
     */
    public function __construct(Client $connector, PrimaryCompanyHelper $primaryCompanyHelper)
    {
        $this->connector            = $connector;
        $this->primaryCompanyHelper = $primaryCompanyHelper;
    }

    /**
     * @param string $content
     * @param mixed  $lead
     *
     * @return string
     */
    public function findTokens($content, $lead)
    {
        $tokens = [];

        // Convert Lead entity to array
        if ($lead instanceof Lead) {
            $lead = $this->primaryCompanyHelper->getProfileFieldsWithPrimaryCompany($lead);
        }

        // Process {getremoteurl=...} tokens
        preg_match_all('/{getremoteurl=(.*?)}/', $content, $matches);
        if (count($matches[0])) {
            foreach ($matches[1] as $k => $url) {
                $token = $matches[0][$k];

                if (isset($tokens[$token])) {
                    continue;
                }
                try {
                    $urlWithoutDecode = str_replace(['|decode', '%7Cdecode'], '', $url);
                    $isDecodeToken    = $urlWithoutDecode !== $url;
                    $url              = $isDecodeToken ? htmlspecialchars_decode(urldecode($urlWithoutDecode)) : $url;
                    $url              = \Mautic\LeadBundle\Helper\TokenHelper::findLeadTokens(
                        str_replace(['[', ']'], ['{', '}'], $url),
                        $lead,
                        true
                    );
                    $data             = $this->connector->get($url, []);
                    $tokens[$token]   = $data->getBody()->getContents();
                } catch (\Exception $e) {
                    $tokens[$token] = '';
                }
            }
        }

        // Process {base64decode=...} tokens
        preg_match_all('/{base64decode=(.*?)}/', $content, $matches);
        if (count($matches[0])) {
            foreach ($matches[1] as $k => $field) {
                $token = $matches[0][$k];

                if (isset($tokens[$token])) {
                    continue;
                }
                $tokens[$token] = (!empty($lead[$field])) ? base64_decode($lead[$field]) : '';
            }
        }

        // Process {encrypt=...} tokens
        preg_match_all('/{encrypt=(.*?)}/', $content, $matches);
        if (count($matches[0])) {
            foreach ($matches[1] as $k => $field) {
                $token = $matches[0][$k];

                if (isset($tokens[$token])) {
                    continue;
                }
                $tokens[$token] = (!empty($lead[$field])) ? $this->encrypt($lead[$field]) : '';
            }
        }

        // Process {decrypt=...} tokens
        preg_match_all('/{decrypt=(.*?)}/', $content, $matches);
        if (count($matches[0])) {
            foreach ($matches[1] as $k => $encryptedData) {
                $token = $matches[0][$k];

                if (isset($tokens[$token])) {
                    continue;
                }
                $tokens[$token] = $this->decrypt($encryptedData);
            }
        }

        return str_replace(array_keys($tokens), $tokens, $content);
    }

    /**
     * Encrypt data using passphrase.
     *
     * @param string $data
     *
     * @return string
     */
    public function encrypt($data)
    {
        $passphrase = $this->getPassphrase();
        $method     = 'AES-256-CBC';
        $key        = hash('sha256', $passphrase, true);
        $iv         = openssl_random_pseudo_bytes(16);
        $encrypted  = openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv);

        // Return the IV and encrypted data encoded in base64
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt data using passphrase.
     *
     * @param string $data
     *
     * @return string
     */
    public function decrypt($data)
    {
        $passphrase = $this->getPassphrase();
        $method     = 'AES-256-CBC';
        $key        = hash('sha256', $passphrase, true);
        $data       = base64_decode($data);
        $iv         = substr($data, 0, 16);
        $encrypted  = substr($data, 16);
        $decrypted  = openssl_decrypt($encrypted, $method, $key, OPENSSL_RAW_DATA, $iv);

        return $decrypted;
    }

    /**
     * Get the passphrase from ENV or use a default value.
     *
     * @return string
     */
    private function getPassphrase()
    {
        $passphrase = getenv('ENCRYPTION_PASSPHRASE');
        if (!$passphrase) {
            $passphrase = 'default_passphrase'; // Use your default passphrase here
        }

        return $passphrase;
    }
}
