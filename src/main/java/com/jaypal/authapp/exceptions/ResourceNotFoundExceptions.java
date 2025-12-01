package com.jaypal.authapp.exceptions;

public class ResourceNotFoundExceptions extends RuntimeException{
    public ResourceNotFoundExceptions(String message){
        super(message);
    }

    public ResourceNotFoundExceptions(){
        super("Resource Not Found!!");
    }
}
