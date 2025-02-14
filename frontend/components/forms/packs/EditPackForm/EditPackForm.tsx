import React, { useState } from "react";
import useDeepEffect from "hooks/useDeepEffect";

import Button from "components/buttons/Button";

import { IQuery } from "interfaces/query";
import { IScheduledQuery } from "interfaces/scheduled_query";
import { ITarget, ITargetsAPIResponse } from "interfaces/target";
// @ts-ignore
import InputField from "components/forms/fields/InputField";
// @ts-ignore
import SelectTargetsDropdown from "components/forms/fields/SelectTargetsDropdown";
import PackQueriesListWrapper from "components/queries/PackQueriesListWrapper";

const baseClass = "edit-pack-form";

interface IEditPackForm {
  className?: string;
  handleSubmit: (formData: IEditPackFormData) => void;
  onCancelEditPack: () => void;
  onFetchTargets?: (
    query: IQuery,
    targetsResponse: ITargetsAPIResponse
  ) => boolean;
  onAddPackQuery: () => void;
  onEditPackQuery: (selectedQuery: IScheduledQuery) => void;
  onRemovePackQueries: (selectedTableQueryIds: number[]) => void;
  targetsCount?: number;
  isPremiumTier?: boolean;
  formData: IEditPackFormData;
  scheduledQueries: IScheduledQuery[];
  isLoadingPackQueries: boolean;
}

interface IEditPackFormData {
  name: string;
  description: string;
  targets: ITarget[];
}

const EditPackForm = ({
  className,
  handleSubmit,
  onCancelEditPack,
  onFetchTargets,
  onAddPackQuery,
  onEditPackQuery,
  onRemovePackQueries,
  scheduledQueries,
  isLoadingPackQueries,
  targetsCount,
  isPremiumTier,
  formData,
}: IEditPackForm): JSX.Element => {
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [packName, setPackName] = useState<string>(formData.name);
  const [packDescription, setPackDescription] = useState<string>(
    formData.description
  );
  const [packFormTargets, setPackFormTargets] = useState<ITarget[]>(
    formData.targets
  );

  useDeepEffect(() => {
    if (formData.targets) {
      setPackFormTargets(formData.targets);
    }
  }, [formData]);

  const onChangePackName = (value: string) => {
    setPackName(value);
  };

  const onChangePackDescription = (value: string) => {
    setPackDescription(value);
  };

  const onChangePackTargets = (value: ITarget[]) => {
    setPackFormTargets(value);
  };

  const onFormSubmit = (): void => {
    if (packName === "") {
      return setErrors({
        ...errors,
        name: "Pack name must be present",
      });
    }

    handleSubmit({
      name: packName,
      description: packDescription,
      targets: [...packFormTargets],
    });
  };

  return (
    <form
      className={`${baseClass} ${className}`}
      onSubmit={onFormSubmit}
      autoComplete="off"
    >
      <h1>Edit pack</h1>
      <InputField
        onChange={onChangePackName}
        value={packName}
        placeholder="Name"
        label="Name"
        name="name"
        error={errors.name}
        inputWrapperClass={`${baseClass}__pack-title`}
      />
      <InputField
        onChange={onChangePackDescription}
        value={packDescription}
        inputWrapperClass={`${baseClass}__pack-description`}
        label="Description"
        name="description"
        placeholder="Add a description of your pack"
        type="textarea"
      />
      <SelectTargetsDropdown
        label="Select pack targets"
        name="selected-pack-targets"
        onFetchTargets={onFetchTargets}
        onSelect={onChangePackTargets}
        selectedTargets={packFormTargets}
        targetsCount={targetsCount}
        isPremiumTier={isPremiumTier}
      />
      <PackQueriesListWrapper
        onAddPackQuery={onAddPackQuery}
        onEditPackQuery={onEditPackQuery}
        onRemovePackQueries={onRemovePackQueries}
        scheduledQueries={scheduledQueries}
        isLoadingPackQueries={isLoadingPackQueries}
      />
      <div className={`${baseClass}__pack-buttons`}>
        <Button onClick={onCancelEditPack} type="button" variant="inverse">
          Cancel
        </Button>
        <Button onClick={onFormSubmit} variant="brand">
          Save
        </Button>
      </div>
    </form>
  );
};

export default EditPackForm;
