package cn.edu.xmu.privilegegateway;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResponseCode {

    private Integer errno;
    private String errmsg;
}
