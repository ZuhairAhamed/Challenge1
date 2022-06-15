package com.challenge.authentication.model;

import lombok.*;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JwtRequest {

    @NotNull(message="UserName cannot be null")
    @NotEmpty(message="UserName cannot be empty")
    private String username;

    @NotNull(message="Password cannot be null")
    @NotEmpty(message="Password cannot be empty")
    private String password;
}
