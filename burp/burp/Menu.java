package burp;

import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import java.util.List;

public class Menu implements IContextMenuFactory
{
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        final List<JMenuItem> menus = new ArrayList<JMenuItem>();
        final JMenuItem ScanItem = new JMenuItem("Send to Shadow Border");
        ScanItem.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent arg0) {
                final IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                final IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(iReqResp);
                final IHttpService iHttpService = iReqResp.getHttpService();
                final byte[] request = iReqResp.getRequest();
                try {
                    String protocol = iHttpService.getProtocol();
                    Integer port = iHttpService.getPort();
                    Util util = new Util();
                    String[] parseResult = util.requestParse(reqInfo, request, protocol, port).split(";");
                    util.redis.RedisTask(parseResult[0], parseResult[1]);
                }
                catch (Exception e) {
                    BurpExtender.log("stderror","[!] Fail in parseResult or RedisTask;");
                    BurpExtender.log("stderror", e.getMessage());
                }
            }
        });
        menus.add(ScanItem);
        return menus;
    }
}
