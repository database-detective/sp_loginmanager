SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE OR ALTER  PROCEDURE [dbo].[sp_loginmanager]
    @Action NVARCHAR(25)
    = 'Info'
    /* Actions:
    Info : Returns a record set for login information
    CreateMetadataTable : Creates the metadata table.
    CreateConfigTable
    SetMetaData : Upsert row in metadata table
    SetConfig
    ExpireNotification
    */
    ,
    @Login sysname              = NULL ,
    @Value NVARCHAR(4000)       = NULL ,
    @Key sysname                = NULL ,
    @Type sysname               = NULL ,
    @Description NVARCHAR(1000) = NULL ,
    @Debug       BIT            = 0
    WITH RECOMPILE
AS
SET NOCOUNT ON;
SET STATISTICS XML OFF;
/* Global variables */
DECLARE @daSQL NVARCHAR(MAX) = N'', @Msg nvarchar(max) = N'';
/* Action : INFO */
IF
 (@Action = 'Info')
    BEGIN
		IF @Debug = 1
        BEGIN
        	RAISERROR(N'Action = Info',0,1) WITH NOWAIT;
        END
	    
        /* Find all SQL Logins */
        SELECT sp.name
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') )      days_until_expiration
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'IsExpired') )                is_expired
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'IsLocked') )                 is_locked
          , m.Name 
          , m.Email
          , sp.principal_id
          , sp.sid
          , sp.is_disabled
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'BadPasswordCount') )         bad_password_count
          , CONVERT(DATETIME, LOGINPROPERTY(sp.name, 'BadPasswordTime') )     bad_password_time
          , CONVERT(sysname, LOGINPROPERTY(sp.name, 'DefaultDatabase') )      default_database
          , CONVERT(sysname, LOGINPROPERTY(sp.name, 'DefaultLanguage') )      default_language
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'HistoryLength') )            history_length
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'IsMustChange') )             is_must_change
          , CONVERT(DATETIME, LOGINPROPERTY(sp.name, 'LockoutTime') )         lockout_time
          , CONVERT(VARBINARY(MAX), LOGINPROPERTY(sp.name, 'PasswordHash') )  password_hash
          , CONVERT(DATETIME, LOGINPROPERTY(sp.name, 'PasswordLastSetTime') ) password_last_set_time
          , CONVERT(INT, LOGINPROPERTY(sp.name, 'PasswordHashAlgorithm') )    password_hash_algorithm
          , CASE (
                    CONVERT(INT, LOGINPROPERTY(sp.name, 'PasswordHashAlgorithm') ) )
                WHEN 0
                    THEN N'SQL7.0'
                WHEN 1
                    THEN N'SHA-1'
                WHEN 2
                    THEN N'SHA-2'
                ELSE NULL
            END                    password_hash_algorithm_desc
        FROM sys.server_principals sp
          left join dbo.loginmanager_metadata m on m.LoginName = sp.name 
        WHERE sp.Type = 'S'
        AND sp.name NOT IN ('##MS_PolicyEventProcessingLogin##'
                       , '##MS_PolicyTsqlExecutionLogin##');
        RETURN;
    END
/* Action: CreateMetadataTable */
IF
 ( @Action = 'CreateMetadataTable')
    BEGIN
	    IF @Debug = 1
        BEGIN
        	RAISERROR(N'Action = CreateMetadataTable',0,1) WITH NOWAIT;
        END
        SET @daSQL = N'';
        /* Create base table */
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.tables t
            WHERE schema_name(t.schema_id) = N'dbo'
            AND t.name                     = N'loginmanager_metadata' )
            BEGIN
                SET @daSQL = N'CREATE TABLE dbo.loginmanager_metadata ( LoginName sysname NOT NULL PRIMARY KEY CLUSTERED ); ';
               
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Creating dbo.loginmanager_metadata',0,1) WITH NOWAIT;
		        END
                EXEC sp_executeSQL @daSQL;
            END
        /* Add email column */
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.columns c
            WHERE object_SCHEMA_NAME(c.object_id) = N'dbo'
            AND OBJECT_NAME(c.object_id)          = N'loginmanager_metadata'
            AND c.name                            = 'Email' )
            BEGIN
                SET @daSQL = N'ALTER TABLE dbo.loginmanager_metadata ADD Email nvarchar(320) NULL ; ';
                
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Adding dbo.loginmanager_metadata.Email column',0,1) WITH NOWAIT;
		        END
                EXEC sp_executeSQL @daSQL;
            END
        /* Add name column */
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.columns c
            WHERE object_SCHEMA_NAME(c.object_id) = N'dbo'
            AND OBJECT_NAME(c.object_id)          = N'loginmanager_metadata'
            AND c.name                            = 'Name' )
            BEGIN
                SET @daSQL = N'ALTER TABLE dbo.loginmanager_metadata ADD Name nvarchar(120) NULL ; ';
                
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Adding dbo.loginmanager_metadata.Name column',0,1) WITH NOWAIT;
		        END
                EXEC sp_executeSQL @daSQL;
            END
        RETURN;
    END
/* Action = CreateMetadataTable */
/* Action: CreateConfigTable */
IF
 ( @Action = 'CreateConfigTable')
    BEGIN
	    IF @Debug = 1
        BEGIN
        	RAISERROR(N'Action = CreateConfigTable',0,1) WITH NOWAIT;
        END
        
        SET @daSQL = N'';
        /* Create base table */
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.tables t
            WHERE schema_name(t.schema_id) = N'dbo'
            AND t.name                     = N'loginmanager_config' )
            BEGIN
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Creating dbo.loginmanager_config',0,1) WITH NOWAIT;
		        END
                CREATE TABLE dbo.loginmanager_config
                    (
                        [config_key] sysname NOT NULL CONSTRAINT pk_loginmanager_config PRIMARY KEY CLUSTERED
                        , [config_value] [nvarchar](4000) NULL
                        , [config_type] sysname NOT NULL
                        , [Description] [nvarchar](1000) NULL
                    )
                ON [PRIMARY]
            END
            RETURN;
    END
/* Action = CreateConfigTable */
/* Action: SetMetadata */
IF
 ( @Action = 'SetMetadata')
    BEGIN
        /* Required Parameters:
        @Login = Name of the login
        @Key = The field to set
        @Value = The value to set
        */
	    IF @Debug = 1
        BEGIN
        	RAISERROR(N'Action = SetMetadata',0,1) WITH NOWAIT;
        END
        
        SELECT @Key      = TRIM(@Key)
          , @Value       = TRIM(@Value)
          , @Type        = COALESCE(TRIM(@Type), 'string')
          , @Description = TRIM(@Description);
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.server_principals
            WHERE name = @Login)
            BEGIN
				RAISERROR(N'Login not found.',0,1)
				WITH NOWAIT;
				RETURN;
            END
        IF
        @Key = N'email'
            BEGIN
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Setting email metadata',0,1) WITH NOWAIT;
		        END
                UPDATE
                    dbo.loginmanager_metadata
                SET
                    email       = @Value
                WHERE LoginName = @Login;
                IF
                 (@@ROWCOUNT = 0)
                    BEGIN
                        INSERT INTO dbo.loginmanager_metadata
                            (
                                LoginName,
                                Email
                            )
                        VALUES
                            (
                                @login,
                                @Value
                            )
                        ;
                    END
            END
        IF
        @Key = N'name'
            BEGIN
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Setting name metadata',0,1) WITH NOWAIT;
		        END
                UPDATE
                    dbo.loginmanager_metadata
                SET
                    name        = @Value
                WHERE LoginName = @Login;
                IF
                 (@@ROWCOUNT = 0)
                    BEGIN
                        INSERT INTO dbo.loginmanager_metadata
                            (
                                LoginName,
                                name
                            )
                        VALUES
                            (
                                @login,
                                @Value
                            )
                        ;
                    END
            END
       
        RETURN;
    END
/* Action = SetMetadata */
/* Action: SetConfig */
IF
 ( @Action = 'SetConfig')
    BEGIN
        /* Required Parameters:
        @Key = The field to set
        @Value = The value to set
        @Type
        @Description
        */
	    IF @Debug = 1
        BEGIN
        	RAISERROR(N'Action = SetConfig',0,1) WITH NOWAIT;
        END
        SELECT @Key      = TRIM(@Key)
          , @Value       = TRIM(@Value)
          , @Type        = COALESCE(TRIM(@Type), 'string')
          , @Description = TRIM(@Description);
        UPDATE
            dbo.loginmanager_config
        SET
            config_value = @Value                      ,
            config_type  = COALESCE(@Type,config_type) ,
            description  = COALESCE(@Description,description)
        WHERE config_key = @Key;
        IF
         (@@ROWCOUNT = 0)
            BEGIN
                INSERT INTO dbo.loginmanager_config
                    (
                        config_key  ,
                        config_value,
                        config_type ,
                        description
                    )
                VALUES
                    (
                        @Key  ,
                        @Value,
                        @Type ,
                        @Description
                    )
                ;
            END
        
        RETURN;
    END
/* Action = SetConfig */
    
/* Action: VerifyDatabaseMail */
IF
 ( @Action IN ( N'VerifyDatabaseMail', N'ExpireNotification' ) )
    BEGIN
        /* Check to see if service broker is enabled in msdb ( default = yes ) */
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.databases
            WHERE name            = 'msdb'
            AND is_broker_enabled = 1)
            BEGIN
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Error: msdb_service_broker_disabled',0,1) WITH NOWAIT;
		        END
                EXEC sp_loginmanager @Action='ThrowError',
                    @Type                   = 'msdb_service_broker_disabled';
            END
        /* Check to see if Database Mail is enabled ( default = no ) */
        IF
        NOT EXISTS (
            SELECT 1
            FROM sys.configurations
            WHERE name       = 'Database Mail XPs'
            AND value_in_use = 1)
            BEGIN
			    IF @Debug = 1
		        BEGIN
		        	RAISERROR(N'Error: database_mail_disabled',0,1) WITH NOWAIT;
		        END
                EXEC sp_loginmanager @Action='ThrowError',
                    @Type                   = 'database_mail_disabled';
            END
    END
/* Action = VerifyDatabaseMail */
    
/* Action: ExpireNotification */
IF
 ( @Action = 'ExpireNotification')
    BEGIN
	    IF @Debug = 1
	    BEGIN
	    	RAISERROR(N'Action = ExpireNotification',0,1) WITH NOWAIT;
	    END
	    
        DECLARE @ExpireNotificationLevel1 INT = COALESCE( ( SELECT TRY_CONVERT(INT, config_value)
												            FROM dbo.loginmanager_config
												            WHERE config_key = 'ExpireNotificationLevel1'), 90 ) 
              , @ExpireNotificationLevel2 INT = COALESCE( ( SELECT TRY_CONVERT(INT, config_value)
													        FROM dbo.loginmanager_config
													        WHERE config_key = 'ExpireNotificationLevel2'), 21 ) 
			  , @ExpireNotificationLevel3 INT = COALESCE( ( SELECT TRY_CONVERT(INT, config_value)
												            FROM dbo.loginmanager_config
												            WHERE config_key = 'ExpireNotificationLevel3'), 14 ) 
			  , @ExpireNotificationLevel4 INT = COALESCE( ( SELECT TRY_CONVERT(INT, config_value)
											                FROM dbo.loginmanager_config
											                WHERE config_key = 'ExpireNotificationLevel4'), 7 ) 
			  , @DefaultEmail NVARCHAR(1000) = COALESCE( (  SELECT config_value
										                    FROM dbo.loginmanager_config
										                    WHERE config_key = 'ExpireNotificationDefaultEmail'), '' ) 
			  , @MailProfile sysname = COALESCE( (  SELECT config_value
							                        FROM dbo.loginmanager_config
							                        WHERE config_key = 'MailProfile'), 'Default Profile' ) 
              , @ExpireNotificationEmailSubjectTemplate NVARCHAR(4000) = COALESCE( (    SELECT config_value
															                            FROM dbo.loginmanager_config
															                            WHERE config_key = 'ExpireNotificationEmailSubjectTemplate'), 'Password expiring soon' ) 
			  , @ExpireNotificationEmailBodyTemplate NVARCHAR(4000) = COALESCE( (   SELECT config_value
													                                FROM dbo.loginmanager_config
													                                WHERE config_key = 'ExpireNotificationEmailBodyTemplate'), 'Password expiring for %s on %s in %i days.' ) 
			  , @LoginName SYSNAME                                                                                
              , @DaysUntilExpiration INT                                                                          
              , @NotificationLevel   TINYINT                                                                      
              , @MetaName            NVARCHAR(1000)                                                               
              , @MetaEmail           NVARCHAR(1000)                                                               
              , @EmailSubject        NVARCHAR(4000)                                                               
              , @EmailBody           NVARCHAR(4000)

        DECLARE cur_NotificationEmails CURSOR LOCAL FAST_FORWARD FOR
	       SELECT sp.name
	          , CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) days_until_expiration
	          , 1                                                            [NotificationLevel]
	          , m.Name
	          , m.Email
	          , FORMATMESSAGE(@ExpireNotificationEmailSubjectTemplate, @@SERVERNAME )                                                                     [Subject]
	          , FORMATMESSAGE(@ExpireNotificationEmailBodyTemplate, sp.name, @@SERVERNAME, CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) ) [Body]
	        FROM sys.server_principals                                                                                                                    sp
	            LEFT JOIN dbo.loginmanager_metadata m
	             ON m.LoginName = sp.name
	        WHERE sp.Type       = 'S'
	        AND sp.name NOT IN ('##MS_PolicyEventProcessingLogin##'
	                          , '##MS_PolicyTsqlExecutionLogin##')
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) = @ExpireNotificationLevel1
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'IsExpired') )           = 0
	        
	        UNION ALL
	        
	        SELECT sp.name
	          , CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) days_until_expiration
	          , 2                                                            [NotificationLevel]
	          , m.Name
	          , m.Email
	          , FORMATMESSAGE(@ExpireNotificationEmailSubjectTemplate, @@SERVERNAME )
	          , FORMATMESSAGE(@ExpireNotificationEmailBodyTemplate, sp.name, @@SERVERNAME, CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) ) [Body]
	        FROM sys.server_principals                                                                                                                    sp
	            LEFT JOIN dbo.loginmanager_metadata m
	             ON m.LoginName = sp.name
	        WHERE sp.Type       = 'S'
	        AND sp.name NOT IN ('##MS_PolicyEventProcessingLogin##'
	                          , '##MS_PolicyTsqlExecutionLogin##')
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) = @ExpireNotificationLevel2
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'IsExpired') )           = 0
	        
	        UNION ALL
	        
	        SELECT sp.name
	          , CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) days_until_expiration
	          , 3                                                            [NotificationLevel]
	          , m.Name
	          , m.Email
	          , FORMATMESSAGE(@ExpireNotificationEmailSubjectTemplate, @@SERVERNAME )
	          , FORMATMESSAGE(@ExpireNotificationEmailBodyTemplate, sp.name, @@SERVERNAME, CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) ) [Body]
	        FROM sys.server_principals                                                                                                                    sp
	            LEFT JOIN dbo.loginmanager_metadata m
	             ON m.LoginName = sp.name
	        WHERE sp.Type       = 'S'
	        AND sp.name NOT IN ('##MS_PolicyEventProcessingLogin##'
	                          , '##MS_PolicyTsqlExecutionLogin##')
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) = @ExpireNotificationLevel3
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'IsExpired') )           = 0
	        
	        UNION ALL
	        
	        SELECT sp.name
	          , CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) days_until_expiration
	          , 4                                                            [NotificationLevel]
	          , m.Name
	          , m.Email
	          , FORMATMESSAGE(@ExpireNotificationEmailSubjectTemplate, @@SERVERNAME )
	          , FORMATMESSAGE(@ExpireNotificationEmailBodyTemplate, sp.name, @@SERVERNAME, CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) ) [Body]
	        FROM sys.server_principals                                                                                                                    sp
	            LEFT JOIN dbo.loginmanager_metadata m
	             ON m.LoginName = sp.name
	        WHERE sp.Type       = 'S'
	        AND sp.name NOT IN ('##MS_PolicyEventProcessingLogin##'
	                          , '##MS_PolicyTsqlExecutionLogin##')
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'DaysUntilExpiration') ) <= @ExpireNotificationLevel4
	        AND CONVERT(INT, LOGINPROPERTY(sp.name, 'IsExpired') )           = 0;
                    
        OPEN cur_NotificationEmails;
                
        FETCH NEXT
        FROM cur_NotificationEmails
        INTO @LoginName
          , @DaysUntilExpiration
          , @NotificationLevel
          , @MetaName
          , @MetaEmail
          , @EmailSubject
          , @EmailBody;
                  
        WHILE (@@FETCH_STATUS = 0)
        BEGIN
            IF @MetaEmail IS NULL
            BEGIN
                SET @MetaEmail = @DefaultEmail;
            END
            BEGIN TRY
                
                IF @Debug = 1
                BEGIN
                    SET @Msg = FORMATMESSAGE(N'Sending notification to %s via email %s', @LoginName, @MetaEmail);
                    RAISERROR(@Msg,0,1) WITH NOWAIT;
                END

                EXEC msdb.dbo.sp_send_dbmail @profile_name=@MailProfile  ,
                    @recipients                           = @MetaEmail   ,
                    @subject                              = @EmailSubject,
                    @body                                 = @EmailBody   ,
                    @body_format                          = 'HTML';
            END TRY
            BEGIN CATCH
                SELECT @LoginName        AS LoginName
                  , @DaysUntilExpiration AS DaysUntilExpiration
                  , @NotificationLevel   AS NotificationLevel
                  , @MetaName            AS MetaName
                  , @MetaEmail           AS MetaEmail
                  , @EmailSubject        AS EmailSubject
                  , @EmailBody           AS EmailBody
                  , ERROR_NUMBER()       AS ErrorNumber
                  , ERROR_STATE()        AS ErrorState
                  , ERROR_SEVERITY()     AS ErrorSeverity
                  , ERROR_PROCEDURE()    AS ErrorProcedure
                  , ERROR_LINE()         AS ErrorLine
                  , ERROR_MESSAGE()      AS ErrorMessage;
            END CATCH
            
            FETCH NEXT
            FROM cur_NotificationEmails
            INTO @LoginName
              , @DaysUntilExpiration
              , @NotificationLevel
              , @MetaName
              , @MetaEmail
              , @EmailSubject
              , @EmailBody;
        END
        RETURN;
    END
/* Action = ExpireNotification */

GO