package sbfs.client;

import java.util.HashMap;
import java.util.Map;

public enum RequestType {
    GET(0), SEND(1), GET_PUBLIC_KEY(2), NONE(3);

    private final int value;
    RequestType(int value) {
        this.value = value;
    }

    public int getValue(){
        return this.value;
    }

    private static final Map<Integer, RequestType> _map = new HashMap<>();
    static
    {
        for (RequestType request : RequestType.values())
            _map.put(request.value, request);
    }

    /**
     * Get Request type from value
     * @param value Value
     * @return RequestType
     */
    public static RequestType from(int value)
    {
        return _map.get(value);
    }
}
