<?php
namespace Tests\Unit;

use Douyuxingchen\PhpWorkWechat\Crypto\XMLParse;
use PHPUnit\Framework\TestCase;

class XMLParseTest extends TestCase
{
    public function testXmlToArray()
    {
        $sPostData = "<xml><ToUserName><![CDATA[toUser]]></ToUserName><AgentID><![CDATA[toAgentID]]></AgentID><Encrypt><![CDATA[msg_encrypt]]></Encrypt></xml>";
        $xmlparse = new XMLParse;
        $array = $xmlparse->extract($sPostData);
        var_dump($array);

        $this->assertTrue(true);
    }
}