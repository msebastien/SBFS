/*
 * All of response types available
 * Author: Sébastien Maes
 */
package sbfs.server;

import java.util.HashMap;
import java.util.Map;

public enum ResponseType {
    OK(10), UNAVAILABLE(11), NOT_RECEIVED(12);

    private final int value;
    ResponseType(int value) {
        this.value = value;
    }

    public int getValue(){
        return this.value;
    }

    private static final Map<Integer, ResponseType> _map = new HashMap<>();
    static
    {
        for (ResponseType response : ResponseType.values())
            _map.put(response.value, response);
    }

    /**
     * Get Response type from value
     * @param value Value
     * @return ResponseType
     */
    public static ResponseType from(int value)
    {
        return _map.get(value);
    }
}
