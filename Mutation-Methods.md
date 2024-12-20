# 变异方法合集

当Agent满足当前环境状态时，它会从动作集合中选择一个动作并将其部署在该状态上，执行的动作是一种变异函数，由于本赛题要求在协议层进行变异，因此变异函数在保持载荷核心部分不变的情况下，通过对协议层内容进行变异而试图绕过WAF，本项目使用的变异方法集合如下：

## 基于资源的绕过

某些WAF为了不影响web服务器的性能，会对校验的用户数据设置大小上限，比如1M。因此可以通过在正常的载荷中插入无害的、随机的干扰数据，使用消耗大的载荷耗尽WAF的计算资源，通过增加传递的参数数量，达到WAF检测上限，超出的参数就可以绕过WAF了，以此扰乱安全机制的判断。在此种情况下，可以构造一个大文件，前面1M的内容为垃圾内容，后面才是真正的恶意载荷，便可以绕过WAF对文件内容的校验。例如：在Content-Disposition字段后添加垃圾数据，来绕过对文件名的校验。

## 基于属性修改的绕过

1）添加额外的Content-Type字段

通过修改 HTTP 请求头中的 Content-Type 字段生成变异载荷。具体来说，函数通过在现有的 Content-Type 字段中附加额外的内容类型（如 application/xml 等），生成多个具有不同 Content-Type 组合的请求。

一些 WAF 可能无法正确解析多个 Content-Type 值的拼接，从而导致对请求内容的误判或跳过检测。某些 WAF 可能只根据规则或签名匹配来判断恶意请求，而这些变异后的请求可能会被视为正常请求，进而规避安全检查。

2）伪造Content-Type字段

通过伪造 HTTP 请求头中的 Content-Type 字段来生成变异请求，以绕过 WAF 的检测。将请求头中的 Content-Type 设置为常见的四种协议类型之一，如 application/x-www-form-urlencoded、multipart/form-data、text/plain 和 application/json，并构造出多个不同的请求载荷。

WAF 通常会根据请求的 Content-Type 来判断传输的数据类型并执行相应的规则匹配。然而，如果 WAF 没有为特定的 Content-Type 协议类型设置匹配规则，传输的数据可能不受检测。例如，multipart/form-data 常用于文件上传，WAF 如果没有处理该协议传输的数据，则可以通过伪造 Content-Type 绕过检测。

函数通过将 Content-Type 设置为不同的协议类型，使请求的格式看起来合法，但实际上传输的内容可能不符合该协议的标准。这样，当 WAF 依据 Content-Type 解析数据时，可能会忽略其中的恶意内容，从而跳过防护措施。

3）修改multipart/form-data的boundary

在 HTTP 请求的 multipart/form-data 传输模式中，boundary 用于分隔不同的表单数据部分，WAF 通常会依据该边界来解析传输的内容。然而，通过对 boundary 进行变异，可以绕过 WAF 的检测规则。

变异方法包括修改 Content-Type 中的 boundary 值，利用多段式的 boundary 结构，基于 RFC 2231 的格式，构造出伪造的边界分隔符。同时，生成两个不同的请求体：一个供 WAF 解析的伪造边界数据，另一个为服务器真实解析的边界数据。通过这种方式，WAF 可能只解析伪造边界部分，而忽略了真正的数据结构，从而避免对实际上传数据的检测。

4）双写upload请求中的文件名

WAF和源站可能出现对文件名解析不一致的情况，如WAF从前向后检测到第一个文件名作为判断依据，而源站每检测到一个文件名就会覆盖上一个文件名，根据此特性可以在攻击载荷中双写请求的文件名，第一个文件名使用伪造的无害后缀，如“.jpg”等，用于绕过WAF检测，而第二个则为实际传递的文件名，可能是木马文件等。

5）为Get请求添加Content-Type请求头

虽然GET请求通常不需要Content-Type头，但可以故意添加此头来混淆服务器。

6）为Get请求的url添加无害干扰命令

在GET请求的URL中可以添加无害的参数来混淆和绕过检测。

7）使用multipart文件传输方法发送请求

通过multipart/form-data编码发送文件可以用于文件上传的攻击，通常配合其他变异方法，例如改变Content-Disposition头等。

8）请求标头欺骗

请求标头欺骗的目标是欺骗 WAF/服务器，让其相信请求来自内部网络。添加一些欺骗性的标头来代表内部网络，就可能可以达到此目的。每次请求时都会同时添加一些标头集，从而欺骗来源。

上游代理/WAF 误解该请求来自其内部网络，并允许恶意负载通过，例如：

X-Originating-IP: 127.0.0.1

X-Forwarded-For: 127.0.0.1

X-Remote-IP: 127.0.0.1

X-Remote-Addr: 127.0.0.1

X-Client-IP: 127.0.0.1

9）删除data中的content-type字段

删除请求数据中的Content-Type字段，攻击者可能绕过某些WAF对请求数据格式的检测。WAF通常通过Content-Type字段来判断数据类型，如果字段被删除，WAF可能无法正确解析数据，从而导致绕过检测。

10）修改Content-Type中的charset属性

通过修改Content-Type头中的charset属性，攻击者可以使用一些不常见或WAF未覆盖的字符集（如ibm037等），从而导致WAF无法正确识别请求中的恶意字符，避免被检测到。

11）设置Accept-Charset属性

通过修改请求的Accept-Charset头，指定一个不常见的字符集（例如utf-32），攻击者可能绕过WAF的字符编码检查。某些WAF可能无法正确解析这些字符集，进而漏掉潜在的恶意负载。

## 基于编码混淆的绕过

1）修改headers大小写

HTTP请求头不区分大小写，但是WAF如果规则设置不完善的话可能会由于大小写而忽略了对该载荷的检测。因此可以通过修改请求头的大小写，伪造HTTP头部以欺骗WAF进行检测，从而绕过某些防护措施。

2）修改载荷的大小写

通过修改载荷中字符的大小写（如将“<script>”修改为“<ScRiPt>”），攻击者可以使WAF难以匹配恶意载荷，从而绕过检测。

3）修改Content-Type的大小写

与HTTP请求头的大小写变异类似，通过源站对大小写不敏感的特性，将请求头中的Content-Type的大小写进行修改来绕过某些严格的过滤器。

4）修改Content-Type中属性名的大小写

在某些情况下，Content-Type中的属性名也不区分大小写，可以对这些属性名进行大小写变异。

5）对载荷进行url编码

在URL中对特殊字符进行URL编码，例如将空格编码为%20，或将/编码为%2F，可以绕过部分过滤机制。

6）对载荷进行unicode编码

将载荷中的字符转化为Unicode编码可以形成变异的恶意请求。部分WAF对Unicode处理不足，可能难以识别这些变体。

7）对载荷进行html编码

攻击者可以将载荷中的字符进行HTML实体编码，如"、>等，从而使载荷中包含的恶意内容变得不容易被WAF识别和过滤。

8）对载荷进行双重编码

通过对载荷进行双重编码（如URL双重编码），攻击者可以将恶意请求进一步混淆，从而绕过一些只检测一级编码的WAF。

9）修改php文件名

攻击者可以修改PHP文件的扩展名，或将文件名包含编码或变形字符（例如“index.php”改为“index.php5”），从而绕过WAF的文件扩展名匹配规则。 

## 基于参数污染的绕过

情况1：服务器使用最后收到的参数，WAF 只检查第一个参数

攻击者可以构造请求，其中包含多个相同名称的参数，服务器使用最后一个参数值，WAF只检查第一个参数。通过这种方式，攻击者可以将恶意数据隐藏在后续的参数中，避开WAF的检查。

情况2：服务器将来自相似参数的值合并，WAF 会单独检查它们

攻击者可以通过添加多个相似的参数，使得服务器将它们合并成一个参数值，而WAF只检查其中一个参数，从而避开对恶意值的检测。

## 利用畸形请求绕过

1）在载荷中添加换行

在请求的payload中插入换行符可能会导致服务器对数据的处理方式不同，尝试绕过特定的输入过滤规则。

2）在载荷中添加空格

通过在载荷中插入额外的空格字符，攻击者可以混淆WAF的规则匹配，使其无法准确判断请求的合法性。

3）在载荷中添加垃圾数据

攻击者可以在请求载荷中插入大量无害的垃圾数据，例如填充无意义的字符或数据，增加请求的大小或复杂性，从而导致WAF难以准确识别恶意部分，进而绕过一些基于正则匹配的WAF。

4）在载荷中添加制表符

通过插入制表符（Tab字符），攻击者可以打乱载荷的结构，干扰WAF的检测规则，绕过其对请求内容的正则匹配。

## 基于分块传输的绕过

分块传输编码允许请求体按块发送，可以通过此方法分段发送恶意请求，避免被安全设备检测到。

## 基于请求类型的绕过

WAF可能会根据HTTP方法的不同来应用不同的规则集。例如，WAF可能会严格检查POST请求中的数据，但对于GET请求则较为宽松。因此，攻击者可能会尝试将一个通常会作为POST请求的操作转换为GET请求，或者反之亦然，以逃避检测。例如，将表单数据编码为URL参数发送，而不是作为POST数据。

除了GET和POST之外，还有其他几种HTTP方法，如HEAD、PUT、DELETE、TRACE、CONNECT和OPTIONS。这些方法中的某些，特别是OPTIONS，通常不会受到同样的审查强度。可以利用这些方法来发送请求，以期绕过WAF的某些规则。