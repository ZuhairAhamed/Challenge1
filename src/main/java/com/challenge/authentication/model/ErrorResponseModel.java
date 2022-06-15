package com.challenge.authentication.model;

import java.util.Date;

public class ErrorResponseModel {

    private Date timeStamp;

    private String errorMessage;

    ErrorResponseModel(){

    }

    public ErrorResponseModel(Date timeStamp, String errorMessage) {
        this.timeStamp = timeStamp;
        this.errorMessage = errorMessage;
    }

    public Date getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(Date timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

}