package util.message;

import java.util.LinkedList;
import java.util.List;

/**
 * Created by lifengshuang on 10/05/2017.
 */
public class MessageHeader {

    private List<MessageHeaderItem> items;

    public MessageHeader() {
        this.items = new LinkedList<>();
    }

    public MessageHeader add(String key, String value) {
        items.add(new MessageHeaderItem(key, value));
        return this;
    }

    public String get(String key) {
        for (MessageHeaderItem item : items) {
            if (item.getKey().equals(key)) {
                return item.getValue();
            }
        }
        return null;
    }

    public static MessageHeader parse(String string) {
        MessageHeader messageHeader = new MessageHeader();
        String[] items = string.split("\n");
        for (String item : items) {
            String[] pair = item.split(":");
            messageHeader.add(pair[0], pair[1]);
        }
        return messageHeader;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (MessageHeaderItem item : items) {
            stringBuilder.append(item.getKey()).append(":").append(item.getValue()).append("\n");
        }
        return stringBuilder.toString();
    }
}
