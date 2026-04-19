package io.apicurio.registry.protobuf.rules.validity;

import com.google.protobuf.DescriptorProtos;
import com.squareup.wire.schema.SchemaException;
import com.squareup.wire.schema.internal.parser.MessageElement;
import com.squareup.wire.schema.internal.parser.ProtoFileElement;
import io.apicurio.registry.content.TypedContent;
import io.apicurio.registry.rest.v3.beans.ArtifactReference;
import io.apicurio.registry.rules.validity.AbstractContentValidator;
import io.apicurio.registry.rules.validity.ValidityLevel;
import io.apicurio.registry.rules.violation.RuleViolationException;
import io.apicurio.registry.types.RuleType;
import io.apicurio.registry.utils.protobuf.schema.FileDescriptorUtils;
import io.apicurio.registry.utils.protobuf.schema.ProtobufFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A content validator implementation for the Protobuf content type.
 */
public class ProtobufContentValidator extends AbstractContentValidator {

    private static final Pattern SAFE_IDENTIFIER_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");

    /**
     * Constructor.
     */
    public ProtobufContentValidator() {
    }

    /**
     * @see io.apicurio.registry.rules.validity.ContentValidator#validate(ValidityLevel, TypedContent, Map)
     */
    @Override
    public void validate(ValidityLevel level, TypedContent content,
                         Map<String, TypedContent> resolvedReferences) throws RuleViolationException {
        if (level == ValidityLevel.SYNTAX_ONLY || level == ValidityLevel.FULL) {
            try {
                validateSecurity(level, content, resolvedReferences);
                if (resolvedReferences == null || resolvedReferences.isEmpty()) {
                    // Parse the protobuf content (syntax validation)
                    ProtoFileElement protoFileElement = ProtobufFile
                            .toProtoFileElement(content.getContent().content());
                    // Attempt semantic validation by building a FileDescriptor
                    // This validates: duplicate tags, invalid tag numbers, unknown types, etc.
                    try {
                        FileDescriptorUtils.protoFileToFileDescriptor(protoFileElement);
                    } catch (RuntimeException e) {
                        // Check if this is a semantic error or a resource loading issue
                        Throwable cause = e.getCause();
                        if (cause instanceof SchemaException) {
                            // Semantic error from Wire's schema linker - re-throw to fail validation
                            throw e;
                        }
                        if (cause instanceof IOException || cause instanceof NullPointerException) {
                            // Resource loading failure (e.g., in native mode where proto resources
                            // may not be available) - fall back to syntax-only validation.
                            // Syntax validation already passed above, so continue.
                            return;
                        }
                        // For other RuntimeExceptions, check the message for semantic error indicators
                        String message = e.getMessage() != null ? e.getMessage() : "";
                        if (message.contains("SchemaException") || message.contains("multiple fields share tag")
                                || message.contains("unable to resolve")) {
                            // This looks like a semantic error - re-throw
                            throw e;
                        }
                        // Unknown error type - fall back to syntax-only to avoid breaking native mode
                    }
                }
                else {
                    // Convert main content if binary (base64-encoded)
                    final ProtoFileElement protoFileElement = ProtobufFile
                            .toProtoFileElement(content.getContent().content());
                    String textMainContent = protoFileElement.toSchema();

                    // Convert references if binary and build required deps map with text content
                    final Map<String, String> requiredDeps = resolvedReferences.entrySet().stream().collect(
                            Collectors.toMap(Map.Entry::getKey,
                                    e -> ProtobufFile.toProtoFileElement(e.getValue().getContent().content()).toSchema()));

                    final Set<FileDescriptorUtils.ProtobufSchemaContent> dependencies = requiredDeps.entrySet()
                            .stream()
                            .map(e -> FileDescriptorUtils.ProtobufSchemaContent.of(e.getKey(), e.getValue()))
                            .collect(Collectors.toSet());

                    MessageElement firstMessage = FileDescriptorUtils.firstMessage(protoFileElement);
                    String fileName = firstMessage != null ? firstMessage.getName() : "schema";

                    FileDescriptorUtils.ProtobufSchemaContent mainFile = FileDescriptorUtils.ProtobufSchemaContent.of(fileName,
                            textMainContent);

                    FileDescriptorUtils.parseProtoFileWithDependencies(mainFile, dependencies, requiredDeps, true, true);
                }
            }
            catch (RuleViolationException rve) {
                throw rve;
            }
            catch (Exception e) {
                throw new RuleViolationException("Syntax violation for Protobuf artifact.", RuleType.VALIDITY,
                        level.name(), e);
            }
        }
    }

    /**
     * @see io.apicurio.registry.rules.validity.ContentValidator#validateReferences(TypedContent, List)
     */
    @Override
    public void validateReferences(TypedContent content, List<ArtifactReference> references)
            throws RuleViolationException {
        try {
            ProtoFileElement protoFileElement = ProtobufFile
                    .toProtoFileElement(content.getContent().content());
            Set<String> allImports = new HashSet<>();
            allImports.addAll(protoFileElement.getImports());
            allImports.addAll(protoFileElement.getPublicImports());

            validateMappedReferences(references, allImports, "Unmapped reference detected.");
        }
        catch (RuleViolationException rve) {
            throw rve;
        }
        catch (Exception e) {
            // Do nothing - we don't care if it can't validate. Another rule will handle that.
        }
    }

    private void validateSecurity(ValidityLevel level, TypedContent content,
                                  Map<String, TypedContent> resolvedReferences) throws RuleViolationException {
        Map<String, String> dependencies = resolvedReferences == null ? Collections.emptyMap()
                : resolvedReferences.entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getKey,
                                entry -> ProtobufFile
                                        .toProtoFileElement(entry.getValue().getContent().content()).toSchema()));

        Map<String, TypedContent> descriptorsToValidate = new LinkedHashMap<>();
        descriptorsToValidate.put("main.proto", content);
        if (resolvedReferences != null) {
            descriptorsToValidate.putAll(resolvedReferences);
        }

        Map<String, byte[]> knownDescriptors = new LinkedHashMap<>();
        for (Map.Entry<String, TypedContent> schemaEntry : descriptorsToValidate.entrySet()) {
            DescriptorProtos.FileDescriptorProto descriptorProto = toFileDescriptorProto(schemaEntry.getValue(),
                    schemaEntry.getKey(), dependencies);
            walkDescriptorTree(descriptorProto, knownDescriptors, level);
        }
    }

    private DescriptorProtos.FileDescriptorProto toFileDescriptorProto(TypedContent content, String fileName,
            Map<String, String> dependencies) {
        String rawContent = content.getContent().content();
        try {
            ProtoFileElement protoFileElement = ProtobufFile.toProtoFileElement(rawContent);
            return FileDescriptorUtils.toFileDescriptorProto(protoFileElement.toSchema(), fileName,
                    Optional.ofNullable(protoFileElement.getPackageName()), dependencies);
        } catch (Exception e) {
            try {
                return DescriptorProtos.FileDescriptorProto.parseFrom(Base64.getDecoder().decode(rawContent));
            } catch (Exception decodeException) {
                RuntimeException runtimeException = new RuntimeException(
                        "Failed to parse Protobuf content as text schema or binary FileDescriptorProto.",
                        decodeException);
                runtimeException.addSuppressed(e);
                throw runtimeException;
            }
        }
    }

    private void walkDescriptorTree(DescriptorProtos.FileDescriptorProto descriptorProto,
                                    Map<String, byte[]> knownDescriptors, ValidityLevel level)
            throws RuleViolationException {
        String packageName = descriptorProto.getPackage();
        for (DescriptorProtos.DescriptorProto messageType : descriptorProto.getMessageTypeList()) {
            walkMessage(messageType, packageName, "", knownDescriptors, level);
        }
        for (DescriptorProtos.EnumDescriptorProto enumType : descriptorProto.getEnumTypeList()) {
            walkEnum(enumType, packageName, "", knownDescriptors, level);
        }
        for (DescriptorProtos.ServiceDescriptorProto serviceType : descriptorProto.getServiceList()) {
            walkService(serviceType, packageName, knownDescriptors, level);
        }
    }

    private void walkMessage(DescriptorProtos.DescriptorProto descriptor, String packageName, String scope,
                             Map<String, byte[]> knownDescriptors, ValidityLevel level)
            throws RuleViolationException {
        validateIdentifier(descriptor.getName(), "message", level);
        String messageScope = scope.isEmpty() ? descriptor.getName() : scope + "." + descriptor.getName();
        String messageFqn = toFqn(packageName, messageScope);
        checkForConflictingDefinition(messageFqn, descriptor.toByteArray(), knownDescriptors, level);

        for (DescriptorProtos.FieldDescriptorProto field : descriptor.getFieldList()) {
            validateIdentifier(field.getName(), "field in " + messageFqn, level);
        }
        for (DescriptorProtos.OneofDescriptorProto oneof : descriptor.getOneofDeclList()) {
            validateIdentifier(oneof.getName(), "oneof in " + messageFqn, level);
        }
        for (DescriptorProtos.DescriptorProto nestedMessage : descriptor.getNestedTypeList()) {
            walkMessage(nestedMessage, packageName, messageScope, knownDescriptors, level);
        }
        for (DescriptorProtos.EnumDescriptorProto nestedEnum : descriptor.getEnumTypeList()) {
            walkEnum(nestedEnum, packageName, messageScope, knownDescriptors, level);
        }
    }

    private void walkEnum(DescriptorProtos.EnumDescriptorProto descriptor, String packageName, String scope,
                          Map<String, byte[]> knownDescriptors, ValidityLevel level)
            throws RuleViolationException {
        validateIdentifier(descriptor.getName(), "enum", level);
        String enumScope = scope.isEmpty() ? descriptor.getName() : scope + "." + descriptor.getName();
        String enumFqn = toFqn(packageName, enumScope);
        checkForConflictingDefinition(enumFqn, descriptor.toByteArray(), knownDescriptors, level);

        for (DescriptorProtos.EnumValueDescriptorProto enumValue : descriptor.getValueList()) {
            validateIdentifier(enumValue.getName(), "enum value in " + enumFqn, level);
        }
    }

    private void walkService(DescriptorProtos.ServiceDescriptorProto descriptor, String packageName,
                             Map<String, byte[]> knownDescriptors, ValidityLevel level)
            throws RuleViolationException {
        validateIdentifier(descriptor.getName(), "service", level);
        String serviceFqn = toFqn(packageName, descriptor.getName());
        checkForConflictingDefinition(serviceFqn, descriptor.toByteArray(), knownDescriptors, level);

        for (DescriptorProtos.MethodDescriptorProto method : descriptor.getMethodList()) {
            validateIdentifier(method.getName(), "rpc method in " + serviceFqn, level);
        }
    }

    private void validateIdentifier(String identifier, String identifierType, ValidityLevel level)
            throws RuleViolationException {
        if (!SAFE_IDENTIFIER_PATTERN.matcher(identifier).matches()) {
            throw new RuleViolationException(
                    "Unsafe Protobuf identifier detected (" + identifierType + "): " + identifier,
                    RuleType.VALIDITY, level.name(), (Throwable) null);
        }
    }

    private void checkForConflictingDefinition(String fqn, byte[] descriptorBytes,
            Map<String, byte[]> knownDescriptors, ValidityLevel level) throws RuleViolationException {
        byte[] knownBytes = knownDescriptors.get(fqn);
        if (knownBytes != null && !Arrays.equals(knownBytes, descriptorBytes)) {
            throw new RuleViolationException("Conflicting Protobuf type definition detected for FQN: " + fqn,
                    RuleType.VALIDITY, level.name(), (Throwable) null);
        }
        knownDescriptors.putIfAbsent(fqn, descriptorBytes);
    }

    private String toFqn(String packageName, String scopeName) {
        if (packageName == null || packageName.isEmpty()) {
            return scopeName;
        }
        if (scopeName == null || scopeName.isEmpty()) {
            return packageName;
        }
        return packageName + "." + scopeName;
    }
}
