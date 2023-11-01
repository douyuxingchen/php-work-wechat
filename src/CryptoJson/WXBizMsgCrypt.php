<?php
namespace Douyuxingchen\PhpWorkWechat\CryptoJson;

use Douyuxingchen\PhpWorkWechat\Crypto\ErrorCode;
use Douyuxingchen\PhpWorkWechat\Crypto\Prpcrypt;
use Douyuxingchen\PhpWorkWechat\Crypto\SHA1;

/**
 * 企业微信回调消息加解密示例代码.
 */
class WXBizMsgCrypt
{
	private $m_sToken;
	private $m_sEncodingAesKey;
	private $m_sReceiveId;

	/**
	 * 构造函数
	 * @param $token string 开发者设置的token
	 * @param $encodingAesKey string 开发者设置的EncodingAESKey
	 * @param $receiveId string, 不同应用场景传不同的id
	 */
	public function __construct($token, $encodingAesKey, $receiveId)
	{
		$this->m_sToken = $token;
		$this->m_sEncodingAesKey = $encodingAesKey;
		$this->m_sReceiveId = $receiveId;
	}

    /**
	* 验证URL
	*/
	public function VerifyURL($sMsgSignature, $sTimeStamp, $sNonce, $sEchoStr, &$sReplyEchoStr)
	{
		if (strlen($this->m_sEncodingAesKey) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt($this->m_sEncodingAesKey);
		//verify msg_signature
		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $sEchoStr);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$signature = $array[1];
		if ($signature != $sMsgSignature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($sEchoStr, $this->m_sReceiveId);
		if ($result[0] != 0) {
			return $result[0];
		}
		$sReplyEchoStr = $result[1];

		return ErrorCode::$OK;
	}
	/**
	 * 将公众平台回复用户的消息加密打包
	 */
	public function EncryptMsg($sReplyMsg, $sTimeStamp, $sNonce, &$sEncryptMsg)
	{
		$pc = new Prpcrypt($this->m_sEncodingAesKey);

		//加密
		$array = $pc->encrypt($sReplyMsg, $this->m_sReceiveId);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}

		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}
		$encrypt = $array[1];

		//生成安全签名
		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $encrypt);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}
		$signature = $array[1];

		//生成发送的json
		$jsonparse = new JsonParse();
		$sEncryptMsg = $jsonparse->generate($encrypt, $signature, $sTimeStamp, $sNonce);
		return ErrorCode::$OK;
	}


	/**
	 * 检验消息的真实性，并且获取解密后的明文.
	 */
	public function DecryptMsg($sMsgSignature, $sTimeStamp = null, $sNonce, $sPostData, &$sMsg)
	{
		if (strlen($this->m_sEncodingAesKey) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt($this->m_sEncodingAesKey);

		//提取密文
		$jsonparse = new JsonParse();
		$array = $jsonparse->extract($sPostData);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}

		$encrypt = $array[1];

		//验证安全签名
		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $encrypt);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$signature = $array[1];
		if ($signature != $sMsgSignature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($encrypt, $this->m_sReceiveId);
		if ($result[0] != 0) {
			return $result[0];
		}
		$sMsg = $result[1];

		return ErrorCode::$OK;
	}

}