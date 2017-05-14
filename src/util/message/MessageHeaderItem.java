package util.message;

/**
 * Created by lifengshuang on 10/05/2017.
 */
public class MessageHeaderItem {
    private String key;
    private String value;

    public MessageHeaderItem(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public String getValue() {
        return value;
    }
}
